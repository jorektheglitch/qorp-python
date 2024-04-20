from __future__ import annotations

from abc import ABC, abstractmethod
from functools import cached_property
from itertools import count
from logging import getLogger, Logger
from secrets import token_bytes
from typing import Callable, NamedTuple, Protocol, TypeAlias

from .addresses import Address, BytesView, ExternalAddress, FullAddress, PubkeyView, address_from_full
from .crypto import CHACHA_NONCE_LENGTH, ChaCha20Poly1305, Ed25519PrivateKey, X25519PrivateKey, X25519PublicKey
from .interactors import FrontendRX, FrontendTX, NetworkRX, NetworkTX, RouterRX, RouterTX
from .packets import Data, RouteError, RouteRequest, RouteResponse, SignedRouteRequest, SignedRouteResponse, QORPPacket
from .packets import RequestInfoTriple
from .utils.futures import Future, ConstFuture, set_ttl
from .utils.timer import Scheduler
from ._types import RouteID


log = getLogger(__name__)

Packet: TypeAlias = QORPPacket
ReceivedResponse = tuple[ExternalAddress, SignedRouteResponse]


class NetworkingProtocol(Protocol):
    @property
    @abstractmethod
    def identity_key(self) -> Ed25519PrivateKey:
        pass

    @abstractmethod
    def attach(self, router: Router) -> NetworkRX:
        pass


class Frontend(ABC):
    @abstractmethod
    def attach(self, terminal: Terminal) -> FrontendRX:
        pass


class RouteInfo(NamedTuple):
    prev_hop: ExternalAddress
    next_hop: ExternalAddress


class RequestInfo(NamedTuple):
    origins: list[ExternalAddress]
    future: Future[ReceivedResponse]


class RouterCallbackRX(RouterRX):
    def __init__(self, terminal: Terminal, callabck: Callable[[ExternalAddress, Packet], Future[None]]) -> None:
        super().__init__()
        self._origin = terminal
        self._callback = callabck

    def send(self, packet: Packet) -> Future[None]:
        origin = ExternalAddress(self._origin.full_address)
        return self._callback(origin, packet)


class NetworkCallbackTX(NetworkTX):
    def __init__(self, callback: Callable[[ExternalAddress, Packet], Future[None]]) -> None:
        super().__init__()
        self._callback = callback

    def send(self, origin: ExternalAddress, packet: Packet) -> Future[None]:
        return self._callback(origin, packet)


class Router:
    _network_rx: NetworkRX
    _scheduler: Scheduler
    _routes: dict[tuple[Address, RouteID], RouteInfo]
    _pending_requests: dict[RequestInfoTriple, RequestInfo]
    _route_request_timeout: float = 10

    def __init__(self,
                 network: NetworkingProtocol,
                 *,
                 scheduler: Scheduler,
                 logger: Logger = log,
                 ) -> None:
        self._scheduler = scheduler
        self._logger = logger or log
        self._pending_requests = {}
        self._routes = {}
        self._terminals: dict[Address, Terminal] = {}
        self._network_rx = network.attach(self)

    @property
    def network_tx(self) -> NetworkTX:
        return NetworkCallbackTX(self.packet_callback)

    def attach(self, terminal: Terminal) -> RouterRX:
        attached = self._terminals.setdefault(terminal.address, terminal)
        if attached is not terminal:
            raise RuntimeError(
                f"Different terminal with address {terminal.address.hex(':', bytes_per_sep=2)} already attached."
            )
        return RouterCallbackRX(terminal=terminal, callabck=self.packet_callback)

    def detach(self, terminal: Terminal) -> None:
        self._terminals.pop(terminal.address, None)

    def packet_callback(self, origin: ExternalAddress, packet: Packet) -> Future[None]:
        if isinstance(packet, Data):
            return self.handle_data(origin, packet)
        elif isinstance(packet, SignedRouteRequest):
            return self.handle_rreq(origin, packet)
        elif isinstance(packet, SignedRouteResponse):
            return self.handle_rrep(origin, packet)
        elif isinstance(packet, RouteError):
            return self.handle_rerr(origin, packet)
        else:
            raise TypeError

    def _forward_packet(self, origin: ExternalAddress, destination: ExternalAddress, packet: Packet) -> Future[None]:
        if (target_terminal := self._terminals.get(address_from_full(FullAddress(destination)))):
            self._logger.debug("Forward %s packet to terminal %s",
                               packet.__class__.__name__, PubkeyView(destination))
            return target_terminal.router_tx.send(origin, packet)
        self._logger.debug("Forward %s packet to %s",
                           packet.__class__.__name__, PubkeyView(destination))
        return self._network_rx.send(destination=destination, packet=packet)

    def _propagate_packet(self, origin: ExternalAddress, packet: SignedRouteRequest) -> Future[None]:
        if (target_terminal := self._terminals.get(packet.payload.destination)):
            self._logger.debug("Propagate %s packet from %s to terminal %s",
                               packet.__class__.__name__, PubkeyView(origin), PubkeyView(target_terminal.full_address))
            return target_terminal.router_tx.send(origin, packet)
        self._logger.debug("Propagate %s packet from %s to Network",
                           packet.__class__.__name__, PubkeyView(origin))
        return self._network_rx.propagate(packet, exclude=origin)

    def handle_data(self, origin: ExternalAddress, data: Data) -> Future[None]:
        route_pair = data.destination, data.route_id
        log_pair = BytesView(data.destination), data.route_id
        self._logger.debug("From %s got Data for %s (route id %s)",
                           PubkeyView(origin), *log_pair)
        route = self._routes.get(route_pair)
        if route is None:
            self._logger.debug("Send RouteError for %s (route id %s)", *log_pair)
            rerr = RouteError(*route_pair)
            return self._network_rx.send(origin, rerr)
        prev_hop, next_hop = route
        if prev_hop != origin:
            self._logger.debug("Drop Data for %s (route id %s) - unexpected origin %s",
                               *log_pair, PubkeyView(origin))
            return ConstFuture(result=None)
        return self._forward_packet(origin=origin, destination=next_hop, packet=data)

    def handle_rreq(self, origin: ExternalAddress, full_request: SignedRouteRequest) -> Future[None]:
        request = full_request.payload
        log_triple = PubkeyView(request.source), request.source_route_id, BytesView(request.destination)
        self._logger.debug("From %s got RouteRequest from %s (%s) for %s",
                           PubkeyView(origin), *log_triple)
        if full_request.hop_count >= request.max_hop_count:
            self._logger.info("Drop RouteRequest from %s (%s) for %s - hop count >= max hop count",
                              *log_triple)
            return ConstFuture(result=None)
        full_request.hop_count += 1
        request_source = address_from_full(request.source)
        if (request_source, request.source_route_id) in self._routes:
            self._logger.info("Drop RouteRequest from %s (%s) for %s - route already established",
                              *log_triple)
            return ConstFuture(result=None)
        request_info = self._register_request(request.info_triple)
        first_seen = (not request_info.origins)
        request_info.origins.append(origin)
        if not first_seen:
            self._logger.debug("Skip propagation of RouteRequest from %s (%s) for %s - not first seen",
                               *log_triple)
            return ConstFuture(result=None)
        self._logger.debug("Propagate RouteRequest from %s (%s) for %s",
                           *log_triple)
        return self._propagate_packet(origin=origin, packet=full_request)

    def handle_rrep(self, origin: ExternalAddress, full_response: SignedRouteResponse) -> Future[None]:
        response = full_response.payload
        log_quad = (BytesView(response.destination), response.source_route_id,
                    PubkeyView(response.source), response.destination_route_id)
        self._logger.debug("From %s got RouteResponse for %s (%s) from %s (%s) ",
                           PubkeyView(origin), *log_quad)
        if full_response.hop_count >= response.max_hop_count:
            self._logger.info("Drop RouteResponse from %s (%s) for %s (%s) - hop count >= max hop count",
                              *log_quad)
            return ConstFuture(result=None)
        full_response.hop_count += 1
        response_source = address_from_full(response.source)
        if (response_source, response.destination_route_id) in self._routes:
            self._logger.info("Drop RouteResponse for %s (%s) from %s (%s) - route already established",
                              *log_quad)
            return ConstFuture(result=None)
        # NOTE: (?) maybe check origin in request_info.origins before popping
        request_info = self._pending_requests.pop(response.request_info_triple, None)
        if request_info is None:
            self._logger.debug("Drop RouteResponse from %s (%s) for %s (%s) - no matched request",
                               *log_quad)
            return ConstFuture(result=None)
        # FIXME: make three-way route setup procedure
        next_hop = request_info.origins[0]
        route_info = RouteInfo(prev_hop=origin, next_hop=next_hop)
        reverse_route_info = RouteInfo(prev_hop=next_hop, next_hop=origin)
        self._logger.debug("Add route to %s (%s): from %s via %s",
                           BytesView(response.destination), response.source_route_id,
                           *map(PubkeyView, route_info))
        self._routes[(response.destination, response.source_route_id)] = route_info
        self._logger.debug("Add route to %s (%s): from %s via %s",
                           BytesView(response_source), response.destination_route_id,
                           *map(PubkeyView, reverse_route_info))
        self._routes[(response_source, response.destination_route_id)] = reverse_route_info
        for request_origin in request_info.origins:
            self._forward_packet(origin=origin, destination=request_origin, packet=full_response)
        return ConstFuture(result=None)

    def handle_rerr(self, origin: ExternalAddress, error: RouteError) -> Future[None]:
        route_pair = error.route_destination, error.route_id
        self._logger.debug("Got RouteError for %s (route id %s)", *route_pair)
        route_info = self._routes.get(route_pair)
        if route_info and route_info.next_hop == origin:
            # TODO: remove reverse route too
            self._routes.pop(route_pair)
            return self._network_rx.send(route_info.prev_hop, error)
        return ConstFuture(result=None)

    def _register_request(self, rreq_info: RequestInfoTriple) -> RequestInfo:
        future: Future[ReceivedResponse] = Future()
        request_info = self._pending_requests.setdefault(rreq_info, RequestInfo([], future))
        if future is request_info.future:
            set_ttl(
                future=future,
                scheduler=self._scheduler,
                ttl=self._route_request_timeout,
                callback=self._forgot_request(rreq_info)
            )
        return request_info

    def _forgot_request(
        self, request_info: RequestInfoTriple
    ) -> Callable[[Future[ReceivedResponse]], None]:
        def callback(future: Future[ReceivedResponse]) -> None:
            self._logger.info("Frogot RouteRequest from %s (%s) for %s - timeout exceed",
                              BytesView(request_info.source), request_info.route_id,
                              BytesView(request_info.destination))
            self._pending_requests.pop(request_info, None)
        return callback


class SessionInfo(NamedTuple):
    id: RouteID
    destination: FullAddress
    next_hop: ExternalAddress
    encryption_key: ChaCha20Poly1305


class SessionsManager:
    _counter: count[int]
    _sessions: dict[int, SessionInfo]

    def __init__(self, sessions: dict[int, SessionInfo] | None = None, counter_start: int | None = None) -> None:
        self._sessions = sessions or {}
        self._counter = count(counter_start or int.from_bytes(token_bytes(4), byteorder='big'))

    def get_next_id(self) -> RouteID:
        return RouteID(next(self._counter))

    def get_session(self, route_id: int) -> SessionInfo | None:
        return self._sessions.get(route_id)

    def create_session(
        self,
        destination: FullAddress,
        *,
        next_hop: ExternalAddress,
        self_key: X25519PrivateKey,
        remote_key: X25519PublicKey,
        session_id: int | None = None
    ) -> SessionInfo:
        session_id = RouteID(session_id or self.get_next_id())
        encryption_key = self._derive_key(self_key, remote_key)
        session = SessionInfo(id=session_id, destination=destination, next_hop=next_hop, encryption_key=encryption_key)
        self._sessions[session_id] = session
        return session

    def remove_session(self, session_id: int) -> None:
        self._sessions.pop(session_id, None)

    def _derive_key(self, private_key: X25519PrivateKey, public_key: X25519PublicKey) -> ChaCha20Poly1305:
        raw_key = private_key.exchange(public_key)
        encryption_key = ChaCha20Poly1305(raw_key)
        return encryption_key


class SessionRequest(NamedTuple):
    id: int
    data_queue: list[bytes]
    ephemeral_key: X25519PrivateKey


class FrontendCallbackTX(FrontendTX):
    def __init__(self, callback: Callable[[Address, bytes], Future[None]]) -> None:
        self._callback = callback

    def send(self, destination: Address, payload: bytes) -> Future[None]:
        return self._callback(destination, payload)


class RouterCallbackTX(RouterTX):
    def __init__(self, callback: Callable[[ExternalAddress, Packet], Future[None]]) -> None:
        self._callback = callback

    def send(self, origin: ExternalAddress, packet: Packet) -> Future[None]:
        return self._callback(origin, packet)


class Terminal:

    def __init__(self,
                 signing_key: Ed25519PrivateKey,
                 router: Router, frontend: Frontend,
                 *,
                 logger: Logger = log,
                 ) -> None:
        self.routes: dict[Address, RouteID] = {}
        self.sessions = SessionsManager()
        self.session_requests: dict[Address, SessionRequest] = {}
        self.signing_key: Ed25519PrivateKey = signing_key
        self._logger = logger
        self._frontend_rx = frontend.attach(self)
        self._router_rx = router.attach(self)

    @cached_property
    def address(self) -> Address:
        return address_from_full(self.full_address)

    @cached_property
    def full_address(self) -> FullAddress:
        return FullAddress(self.signing_key.public_key())

    @property
    def frontend_tx(self) -> FrontendTX:
        return FrontendCallbackTX(self._outgoing_packet_callback)

    @property
    def router_tx(self) -> RouterTX:
        return RouterCallbackTX(self._incoming_packet_callback)

    def _incoming_packet_callback(self, origin: ExternalAddress, packet: Packet) -> Future[None]:
        match packet:
            case Data(_, session_id, chacha_nonce, encrypted_payload):
                session = self.sessions.get_session(session_id)
                self._logger.debug("Got Data for session %s", session_id)
                if not session:
                    self._logger.warning("Drop Data for unknown session %s", session_id)
                    # NOTE: maybe somehow notify other node that session id is invalid?
                    return ConstFuture(result=None)
                payload = session.encryption_key.decrypt(bytes(chacha_nonce), bytes(encrypted_payload), None)
                # TODO: parse payload and process it somehow
                source_short = address_from_full(session.destination)
                self._logger.debug("Pass decrypted payload (session %s) to frontend (%s bytes)",
                                   session_id, len(payload))
                return self._frontend_rx.send(source=source_short, payload=payload)
            case SignedRouteRequest(RouteRequest(_, source, request_id, source_eph)):
                self._logger.debug("Got RouteRequest from %s (%s)",
                                   PubkeyView(source), request_id)
                terminal_eph = X25519PrivateKey.generate()
                session = self.sessions.create_session(
                    destination=source,
                    next_hop=origin,
                    self_key=terminal_eph,
                    remote_key=source_eph
                )
                # TODO: check that there is no existed route info for request
                #       source (it might allow replay attacks)
                # TODO: check that there is no already sended responses
                response = RouteResponse(
                    destination=address_from_full(source),
                    source=self.full_address,
                    source_route_id=request_id,
                    destination_route_id=session.id,
                    destination_eph=terminal_eph.public_key(),
                    max_hop_count=64,
                )
                signed_response = response.sign(signing_key=self.signing_key)
                self._logger.debug("Respond for RouteRequest from %s (%s) with RouteResponse (%s)",
                                   PubkeyView(source), request_id, response.destination_route_id)
                return self._router_rx.send(packet=signed_response)
            case SignedRouteResponse(RouteResponse(_, source, request_id, route_id, destination_eph)):
                source_view = PubkeyView(source)
                self._logger.debug("Got RouteResponse from %s (%s) for %s",
                                   source_view, route_id, request_id)
                existed_session = self.sessions.get_session(request_id)
                if existed_session is None:
                    source_short = address_from_full(source)
                    session_request = self.session_requests.get(source_short)
                    if not session_request:
                        self._logger.info("Drop RouteResponse from %s (%s) for %s - unknown request id",
                                          source_view, route_id, request_id)
                        return ConstFuture(result=None)
                    if session_request.id != request_id:
                        self._logger.info("Drop RouteResponse from %s (%s) for %s - invalid request id",
                                          source_view, route_id, request_id)
                        return ConstFuture(result=None)
                    self._logger.info("Register route to %s (route id %s)",
                                      PubkeyView(source), route_id)
                    self.session_requests.pop(source_short)
                    self.sessions.create_session(
                        destination=source,
                        next_hop=origin,
                        self_key=session_request.ephemeral_key,
                        remote_key=destination_eph,
                        session_id=route_id,
                    )
                    if session_request.data_queue:
                        self._logger.info("Send queued data to %s (route id %s)",
                                          PubkeyView(source), route_id)
                    for data in session_request.data_queue:
                        self._outgoing_packet_callback(destination=source_short, payload=data)
                return ConstFuture(result=None)
            case RouteError(route_destination, session_id):
                # TODO: remove route from routes
                log_pair = (BytesView(route_destination), session_id)
                self._logger.debug("Got RouteError for %s (%s) from %s",
                                   *log_pair, PubkeyView(origin))
                session = self.sessions.get_session(session_id)
                if session is None:
                    self._logger.info("Drop RouteError for %s (%s) - unknown route id",
                                      *log_pair)
                elif origin != session.next_hop:
                    self._logger.warning("Drop RouteError for %s (%s) - unexpected origin %s",
                                         *log_pair, PubkeyView(origin))
                elif route_destination != session.destination:
                    self._logger.warning("Drop RouteError for %s (%s) - incorrect destination",
                                         *log_pair)
                else:
                    self._logger.info("Remove route to %s (%s) - RouteError received",
                                      *log_pair)
                    self.sessions.remove_session(session_id)
                return ConstFuture(result=None)
            case unknown:
                raise ValueError(unknown)

    def _outgoing_packet_callback(self, destination: Address, payload: bytes) -> Future[None]:
        self._logger.debug("Got data from frontend to %s, %s bytes",
                           BytesView(destination), len(payload))
        session_id = self.routes.get(destination)
        if session_id:
            session = self.sessions.get_session(session_id)
            assert session, "Unexpected condition: destination in routes, but session does not exists"
            nonce = token_bytes(CHACHA_NONCE_LENGTH)
            encrypted_data = session.encryption_key.encrypt(nonce, payload, None)
            data_packet = Data(
                destination=destination,
                route_id=session_id,
                chacha_nonce=nonce,
                payload=encrypted_data,
            )
            self._logger.debug("Send Data packet to %s, %s bytes",
                               BytesView(destination), len(encrypted_data))
            return self._router_rx.send(packet=data_packet)
        else:
            session_request = self.session_requests.get(destination)
            if session_request:
                log.debug("Store data for %s (%s) in queue (total %s items)",
                          BytesView(destination), session_request.id, len(session_request.data_queue))
                # TODO: create future for each queue element
                session_request.data_queue.append(payload)
                return ConstFuture(result=None)
            session_id = self.sessions.get_next_id()
            ephemeral_key = X25519PrivateKey.generate()
            session_request = SessionRequest(id=session_id, data_queue=[], ephemeral_key=ephemeral_key)
            self.session_requests[destination] = session_request
            route_request = RouteRequest(
                destination=destination,
                source=self.full_address,
                source_route_id=session_id,
                source_eph=ephemeral_key.public_key(),
                max_hop_count=128,
            )
            self._logger.info("Emit RouteRequest for %s (request id %s)",
                              BytesView(destination), session_id)
            signed_request = route_request.sign(self.signing_key)
            return self._router_rx.send(packet=signed_request)
