from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from itertools import count
from secrets import token_bytes
from typing import Callable, NamedTuple, NewType

from .addresses import Address, ExternalAddress, FullAddress, address_from_full
from .crypto import ChaCha20Poly1305, Ed25519PrivateKey, X25519PublicKey, X25519PrivateKey
from .crypto import CHACHA_NONCE_LENGTH
from .utils.futures import Future, ConstFuture, set_ttl
from .utils.timer import Timer


EMPTY_SET: set[Future[ReceivedResponse]] = set()

log = logging.getLogger(__name__)

RouteID = NewType("RouteID", int)


class Networking(ABC):
    @property
    @abstractmethod
    def identity_key(self) -> Ed25519PrivateKey:
        pass


class NetworkRX(ABC):
    @abstractmethod
    def send(self, destination: ExternalAddress, packet: Packet) -> Future[None]:
        pass

    @abstractmethod
    def propagate(self, packet: Packet, exclude: ExternalAddress) -> Future[None]:
        pass


class RouterRX(ABC):
    @abstractmethod
    def send(self, packet: Packet) -> Future[None]:
        pass


class RouterCallbackRX(RouterRX):
    def __init__(self, terminal: Terminal, callabck: Callable[[ExternalAddress, Packet], Future[None]]) -> None:
        super().__init__()
        self._origin = terminal
        self._callback = callabck

    def send(self, packet: Packet) -> Future[None]:
        origin = ExternalAddress(self._origin.address)
        return self._callback(origin, packet)


class RouterTX(ABC):
    @abstractmethod
    def send(self, origin: ExternalAddress, packet: Packet) -> Future[None]:
        pass


class FrontendRX(ABC):
    @abstractmethod
    def send(self, source: Address, payload: bytes) -> Future[None]:
        pass


class FrontendTX(ABC):
    @abstractmethod
    def send(self, destination: Address, payload: bytes) -> Future[None]:
        pass


@dataclass
class Data:
    destination: Address
    route_id: RouteID
    chacha_nonce: bytes
    payload_length: int
    payload: bytes


@dataclass
class RouteRequest:
    destination: Address
    source: FullAddress
    source_route_id: RouteID
    source_eph: X25519PublicKey
    max_hop_count: int

    @property
    def info_triple(self) -> RequestInfoTriple:
        source = address_from_full(self.source)
        return RequestInfoTriple(source, self.destination, self.source_route_id)

    def sign(self, signing_key: Ed25519PrivateKey) -> SignedRouteRequest:
        pass


@dataclass
class SignedRouteRequest:
    payload: RouteRequest
    sign: bytes
    hop_count: int


@dataclass
class RouteResponse:
    destination: Address
    source: FullAddress
    source_route_id: RouteID
    destination_route_id: RouteID
    destination_eph: X25519PublicKey
    max_hop_count: int

    @property
    def request_info_triple(self) -> RequestInfoTriple:
        source = address_from_full(self.source)
        return RequestInfoTriple(self.destination, source, self.source_route_id)

    def sign(self, signing_key: Ed25519PrivateKey) -> SignedRouteResponse:
        pass


@dataclass
class SignedRouteResponse:
    payload: RouteResponse
    sign: bytes
    hop_count: int


@dataclass
class RouteError:
    route_destination: Address
    route_id: RouteID


Packet = Data | SignedRouteRequest | SignedRouteResponse | RouteError

ReceivedResponse = tuple[ExternalAddress, SignedRouteResponse]


class RouteInfo(NamedTuple):
    prev_hop: ExternalAddress
    next_hop: ExternalAddress


class RequestInfoTriple(NamedTuple):
    source: Address
    destination: Address
    source_route_id: RouteID


class RequestInfo(NamedTuple):
    origins: list[ExternalAddress]
    future: Future[ReceivedResponse]


class Router:
    _network_rx: NetworkRX
    _timer: Timer
    _routes: dict[tuple[Address, RouteID], RouteInfo]
    _pending_requests: dict[RequestInfoTriple, RequestInfo]
    route_request_timeout: float = 10

    def __init__(self) -> None:
        self._terminals: dict[Address, Terminal] = {}

    def attach(self, terminal: Terminal) -> RouterRX:
        address = address_from_full(terminal.address)
        attached = self._terminals.setdefault(address, terminal)
        if attached is not terminal:
            raise RuntimeError(f"Different terminal with address {address.hex(':', bytes_per_sep=2)} already attached.")
        return RouterCallbackRX(terminal=terminal, callabck=self.packet_callback)

    def detach(self, terminal: Terminal) -> None:
        self._terminals.pop(address_from_full(terminal.address), None)

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
            return target_terminal.router_tx.send(origin, packet)
        return self._network_rx.send(destination=destination, packet=packet)

    def _propagate_packet(self, origin: ExternalAddress, packet: SignedRouteRequest) -> Future[None]:
        if (target_terminal := self._terminals.get(packet.payload.destination)):
            return target_terminal.router_tx.send(origin, packet)
        return self._network_rx.propagate(packet, exclude=origin)

    def handle_data(self, origin: ExternalAddress, data: Data) -> Future[None]:
        route_pair = data.destination, data.route_id
        route = self._routes.get(route_pair)
        if route is None:
            rerr = RouteError(*route_pair)
            return self._network_rx.send(origin, rerr)
        prev_hop, next_hop = route
        if prev_hop != origin:
            return ConstFuture(result=None)
        return self._forward_packet(origin=origin, destination=next_hop, packet=data)

    def handle_rreq(self, origin: ExternalAddress, full_request: SignedRouteRequest) -> Future[None]:
        request = full_request.payload
        full_request.hop_count += 1
        if full_request.hop_count > request.max_hop_count:
            return ConstFuture(result=None)
        if (request.source, request.source_route_id) in self._routes:
            return ConstFuture(result=None)
        request_info = self._register_request(request.info_triple)
        first_seen = (not request_info.origins)
        request_info.origins.append(origin)
        if not first_seen:
            return ConstFuture(result=None)
        return self._propagate_packet(origin=origin, packet=full_request)

    def handle_rrep(self, origin: ExternalAddress, full_response: SignedRouteResponse) -> Future[None]:
        response = full_response.payload
        full_response.hop_count += 1
        if full_response.hop_count > response.max_hop_count:
            return ConstFuture(result=None)
        request_info = self._pending_requests.pop(response.request_info_triple, None)
        if request_info:
            request_info.future.set_result((origin, full_response))
        return ConstFuture(result=None)

    def handle_rerr(self, origin: ExternalAddress, error: RouteError) -> Future[None]:
        route_pair = error.route_destination, error.route_id
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
            future.add_done_callback(self._done_request(rreq_info))
            set_ttl(
                future=future,
                timer=self._timer,
                ttl=self.route_request_timeout,
                callback=self._forgot_request(rreq_info)
            )
        return request_info

    def _done_request(
        self, request_info: RequestInfoTriple
    ) -> Callable[[Future[ReceivedResponse]], None]:
        def callback(future: Future[ReceivedResponse]) -> None:
            if future.cancelled() or future.exception():
                return
            futures = self._pending_requests.pop(request_info, None)
            if futures is None:
                return
            next_hop, full_response = future.result()
            response = full_response.payload
            # FIXME: make three-way route setup procedure
            prev_hop = futures.origins[0]
            route_info = RouteInfo(prev_hop=prev_hop, next_hop=next_hop)
            reverse_route_info = RouteInfo(prev_hop=next_hop, next_hop=prev_hop)
            self._routes[(response.destination, response.destination_route_id)] = route_info
            self._routes[(address_from_full(response.source), response.source_route_id)] = reverse_route_info
            for origin in futures.origins:
                self._forward_packet(origin=next_hop, destination=origin, packet=full_response)
        return callback

    def _forgot_request(
        self, request_info: RequestInfoTriple
    ) -> Callable[[Future[ReceivedResponse]], None]:
        def callback(future: Future[ReceivedResponse]) -> None:
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

    def __init__(self, signing_key: Ed25519PrivateKey, router: Router, frontend: Frontend) -> None:
        # raw_pubkey = signing_key.public_key().public_bytes(
        #     encoding=serialization.Encoding.Raw,
        #     format=serialization.PublicFormat.Raw
        # )
        self.address = FullAddress(signing_key.public_key())
        self.routes: dict[Address, RouteID] = {}
        self.sessions = SessionsManager()
        self.session_requests: dict[Address, SessionRequest] = {}
        self.signing_key: Ed25519PrivateKey = signing_key
        self._router_rx = router.attach(self)
        self._frontend_rx = frontend.attach(self)

    @property
    def frontend_tx(self) -> FrontendTX:
        return FrontendCallbackTX(self._outgoing_packet_callback)

    @property
    def router_tx(self) -> RouterTX:
        return RouterCallbackTX(self._incoming_packet_callback)

    def _incoming_packet_callback(self, origin: ExternalAddress, packet: Packet) -> Future[None]:
        match packet:
            case Data(_, session_id, chacha_nonce, _, payload):
                session = self.sessions.get_session(session_id)
                if not session:
                    log.warning("Drop data for unknown session %s", session_id)
                    # NOTE: maybe somehow notify other node that session id is invalid?
                    return ConstFuture(result=None)
                payload = session.encryption_key.decrypt(chacha_nonce, payload, None)
                # TODO: parse payload and process it somehow
                source_short = address_from_full(session.destination)
                return self._frontend_rx.send(source=source_short, payload=payload)
            case RouteRequest(_, source, request_id, source_eph):
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
                    source=self.address,
                    source_route_id=request_id,
                    destination_route_id=session.id,
                    destination_eph=terminal_eph.public_key(),
                    max_hop_count=64,
                )
                signed_response = response.sign(signing_key=self.signing_key)
                return self._router_rx.send(packet=signed_response)
            case RouteResponse(_, source, request_id, route_id, destination_eph):
                existed_session = self.sessions.get_session(request_id)
                if existed_session is None:
                    source_short = address_from_full(source)
                    session_request = self.session_requests.get(source_short)
                    if not session_request or session_request.id != request_id:
                        # got unexpected response or response for unknown request
                        return ConstFuture(result=None)
                    self.session_requests.pop(source_short)
                    self.sessions.create_session(
                        destination=source,
                        next_hop=origin,
                        self_key=session_request.ephemeral_key,
                        remote_key=destination_eph,
                        session_id=route_id,
                    )
                    for data in session_request.data_queue:
                        self._outgoing_packet_callback(destination=source_short, payload=data)
                return ConstFuture(result=None)
            case RouteError(route_destination, session_id):
                # TODO: remove route from routes
                session = self.sessions.get_session(session_id)
                if session is None:
                    log.warning("Got RouteError for unexistent route")
                elif origin != session.next_hop:
                    log.warning("Got RouteError from unexpected direction")
                elif route_destination != session.destination:
                    log.warning("Got incorrect RouteError")
                else:
                    self.sessions.remove_session(session_id)
                return ConstFuture(result=None)
            case unknown:
                raise ValueError(unknown)

    def _outgoing_packet_callback(self, destination: Address, payload: bytes) -> Future[None]:
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
                payload_length=len(encrypted_data),
                payload=encrypted_data,
            )
            return self._router_rx.send(packet=data_packet)
        else:
            session_request = self.session_requests.get(destination)
            if session_request:
                # TODO: create future for each queue element
                session_request.data_queue.append(payload)
                return ConstFuture(result=None)
            session_id = self.sessions.get_next_id()
            ephemeral_key = X25519PrivateKey.generate()
            session_request = SessionRequest(id=session_id, data_queue=[], ephemeral_key=ephemeral_key)
            self.session_requests[destination] = session_request
            route_request = RouteRequest(
                destination=destination,
                source=self.address,
                source_route_id=session_id,
                source_eph=ephemeral_key.public_key(),
                max_hop_count=128,
            )
            signed_request = route_request.sign(self.signing_key)
            return self._router_rx.send(packet=signed_request)


class Frontend(ABC):
    @abstractmethod
    def attach(self, terminal: Terminal) -> FrontendRX:
        pass


class DefaultNetworking(Networking):
    def __init__(self, identity_key: Ed25519PrivateKey) -> None:
        super().__init__()
        self._identity_key = identity_key

    @property
    def identity_key(self) -> Ed25519PrivateKey:
        return self._identity_key


class DefaultFrontendCallbackRX(FrontendRX):
    def __init__(self, terminal: Terminal, callback: Callable[[Address, Address, bytes], Future[None]]) -> None:
        super().__init__()
        self.terminal = terminal
        self.terminal_address = address_from_full(terminal.address)
        self.callback = callback

    def send(self, source: Address, payload: bytes) -> Future[None]:
        return self.callback(source, self.terminal_address, payload)


class DefaultFrontend(Frontend):
    _terminals: dict[FullAddress, Terminal]

    def attach(self, terminal: Terminal) -> FrontendRX:
        self._terminals.setdefault(terminal.address, terminal)
        rx = DefaultFrontendCallbackRX(terminal, self.on_data)
        return rx

    def on_data(self, source: Address, destination: Address, payload: bytes) -> Future[None]:
        return ConstFuture(result=None)


class QORPNode:
    def __init__(self,
                 networking: Networking | None = None,
                 router: Router | None = None,
                 identity_key: Ed25519PrivateKey | None = None,
                 frontend: Frontend | None = None,
                 ) -> None:
        if networking is not None:
            self._networking = networking
            self._identity_key = networking.identity_key
        else:
            self._identity_key = identity_key or Ed25519PrivateKey.generate()
            self._networking = DefaultNetworking(self._identity_key)
        self._router = router or Router()
        self._frontend = frontend or DefaultFrontend()

    def create_terminal(self,
                        signing_key: Ed25519PrivateKey | None = None,
                        factory: Callable[[Ed25519PrivateKey, Router, Frontend], Terminal] = Terminal
                        ) -> Terminal:
        signing_key = signing_key or Ed25519PrivateKey.generate()
        terminal = factory(signing_key, self._router, self._frontend)
        return terminal

    def create_datagram_endpoint(self, port: int, process_datagrams: Callable[[], None]):
        pass

    def listen_connections(self, port: int, process_connection: Callable[[], None]):
        pass

    def open_connection(self, address: Address, port: int):
        pass
