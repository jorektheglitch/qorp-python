from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass
from functools import cached_property
from secrets import randbits, token_bytes
from threading import Thread, Event
import time
import bisect
from collections import deque
from typing import Any, Callable, Generator, Generic, Iterator, NamedTuple, Sequence, TypeVar, overload

from qorp.addresses import Address, ExternalAddress, FullAddress, address_from_full
from qorp.core import Frontend, NetworkingProtocol, Packet, Router, Terminal, RouteID
from qorp.crypto import CHACHA_NONCE_LENGTH, ChaCha20Poly1305, Ed25519PrivateKey, X25519PrivateKey
from qorp.interactors import FrontendRX, NetworkRX
from qorp.packets import Data, RouteError, RouteRequest, RouteResponse, SignedRouteRequest, SignedRouteResponse
from qorp.utils.futures import Future, ConstFuture
from qorp.utils.timer import Callback, Scheduler, ScheduleHandle, Args


Item = TypeVar("Item", covariant=True)


class SequenceProxy(Sequence[Item]):
    def __init__(self, origin: Sequence[Item]) -> None:
        super().__init__()
        self._origin = origin

    def index(self, value: Any, start: int = 0, stop: int | None = None) -> int:  # type: ignore
        if stop is None:
            return self._origin.index(value, start)
        return self._origin.index(value, start, stop)

    def count(self, value: Any) -> int:  # type: ignore
        return self._origin.count(value)

    def __bool__(self) -> bool:
        return bool(self._origin)

    def __contains__(self, value: object) -> bool:
        return self._origin.__contains__(value)

    @overload
    def __getitem__(self, index: int) -> Item: pass
    @overload
    def __getitem__(self, index: slice) -> SequenceProxy[Item]: pass

    def __getitem__(self, index: int | slice) -> Item | SequenceProxy[Item]:
        if isinstance(index, int):
            return self._origin.__getitem__(index)
        items = self._origin.__getitem__(index)
        return SequenceProxy(items)

    def __iter__(self) -> Iterator[Item]:
        return self._origin.__iter__()

    def __len__(self) -> int:
        return self._origin.__len__()

    def __reversed__(self) -> Iterator[Item]:
        return self._origin.__reversed__()

    def __str__(self) -> str:
        return f"{self.__class__.__name__}({str(self._origin)})"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({repr(self._origin)})"


class FrontendCallbackRX(FrontendRX):
    def __init__(self, terminal: Terminal, callback: Callable[[Address, Address, bytes], Future[None]]) -> None:
        self._terminal = terminal
        self._callback = callback

    def send(self, source: Address, payload: bytes) -> Future[None]:
        return self._callback(source, self._terminal.address, payload)


class CallbackFrontend(Frontend, ABC):
    def __init__(self) -> None:
        super().__init__()
        self._terminals: dict[Address, Terminal] = {}

    def attach(self, terminal: Terminal) -> FrontendRX:
        attached = self._terminals.setdefault(terminal.address, terminal)
        if attached is not terminal:
            raise RuntimeError(
                f"Diffenert terminal with adress {terminal.address.hex(':', bytes_per_sep=2)} already attached."
            )
        return FrontendCallbackRX(terminal, self.on_data)

    @abstractmethod
    def on_data(self, source: Address, destination: Address, payload: bytes) -> Future[None]:
        raise NotImplementedError


class StoringFrontend(CallbackFrontend):
    def __init__(self) -> None:
        super().__init__()
        self._received: list[tuple[Address, Address, bytes]] = []

    @property
    def received(self) -> Sequence[tuple[Address, Address, bytes]]:
        return SequenceProxy(self._received)

    def on_data(self, source: Address, destination: Address, payload: bytes) -> Future[None]:
        self._received.append((source, destination, payload))
        return ConstFuture(result=None)


class EchoFrontend(CallbackFrontend):
    def on_data(self, source: Address, destination: Address, payload: bytes) -> Future[None]:
        return self._terminals[destination].frontend_tx.send(source, payload)


class NOOPFrontend(CallbackFrontend):
    def on_data(self, source: Address, destination: Address, payload: bytes) -> Future[None]:
        return ConstFuture(result=None)


class NetworkingCallbackRX(NetworkRX):
    def __init__(self,
                 router: Router,
                 send_callback: Callable[[Packet, Router, ExternalAddress], Future[None]],
                 propagate_callback: Callable[[Packet, Router, ExternalAddress], Future[None]],
                 ) -> None:
        super().__init__()
        self._router = router
        self._send_callback = send_callback
        self._propagate_callback = propagate_callback

    def send(self, destination: ExternalAddress, packet: Packet) -> Future[None]:
        return self._send_callback(packet, self._router, destination)

    def propagate(self, packet: Packet, exclude: ExternalAddress) -> Future[None]:
        return self._propagate_callback(packet, self._router, exclude)


class EmulatedNetworking(NetworkingProtocol):
    def __init__(self) -> None:
        self._emulated_nodes: set[EmulatedNode] = set()
        self._identity_key = Ed25519PrivateKey.generate()
        self._routers: set[Router] = set()
        self._received: list[tuple[Packet, ExternalAddress]] = []
        self._propagated: list[tuple[Packet, ExternalAddress]] = []

    @property
    def identity_key(self) -> Ed25519PrivateKey:
        return self._identity_key

    @property
    def received(self) -> Sequence[tuple[Packet, ExternalAddress]]:
        return SequenceProxy(self._received)

    @property
    def propagated(self) -> Sequence[tuple[Packet, ExternalAddress]]:
        return SequenceProxy(self._propagated)

    def attach(self, router: Router) -> NetworkRX:
        self._routers.add(router)
        return NetworkingCallbackRX(router, self.on_packet, self.on_propagate_packet)

    def detach(self, router: Router) -> None:
        try:
            self._routers.remove(router)
        except KeyError:
            pass

    def is_attached(self, router: Router) -> bool:
        return router in self._routers

    def add_node(self,
                 private_key: Ed25519PrivateKey | None = None,
                 *,
                 packet_generator: PacketGenerator
                 ) -> EmulatedNode:
        node = EmulatedNode(private_key=private_key, networking=self, packet_generator=packet_generator)
        self._emulated_nodes.add(node)
        return node

    def is_emulated_nodes_attached(self, *nodes: EmulatedNode) -> bool:
        return self._emulated_nodes.issuperset(nodes)

    def on_packet(self, packet: Packet, from_router: Router, destination: ExternalAddress) -> Future[None]:
        self._received.append((packet, destination))
        return ConstFuture(result=None)

    def on_propagate_packet(self, packet: Packet, from_router: Router, exclude: ExternalAddress) -> Future[None]:
        self._propagated.append((packet, exclude))
        return ConstFuture(result=None)


class EmulatedNode:
    def __init__(self,
                 private_key: Ed25519PrivateKey | None = None,
                 *,
                 networking: EmulatedNetworking,
                 packet_generator: PacketGenerator,
                 ) -> None:
        self._networking = networking
        self._origin_addr = ExternalAddress(Ed25519PrivateKey.generate().public_key())
        self._private_signing = private_key or Ed25519PrivateKey.generate()
        self._packet_generator = packet_generator

    @cached_property
    def address(self) -> Address:
        return address_from_full(self.full_address)

    @cached_property
    def full_address(self) -> FullAddress:
        return FullAddress(self._private_signing.public_key())

    @cached_property
    def origin_address(self) -> ExternalAddress:
        return self._origin_addr

    def establish_session(self,
                          destination: Address,
                          *,
                          via_router: Router,
                          ) -> EmulatedSession:
        if not self._networking.is_attached(via_router):
            raise RuntimeError("Trying to attach via unbound router")
        request, _, rreq_source_eph_priv = self._packet_generator.create_rreq(
            destination=destination,
            source_priv=self._private_signing,
        )
        via_router.network_tx.send(self.origin_address, request).result()
        response = self._find_response_for(request, self._networking.received)
        assert response, \
            "Got no response for RouteRequest"
        session = emulated_session(request, rreq_source_eph_priv, response, self._packet_generator)
        return session

    def establish_transit_session(self,
                                  destination: EmulatedNode,
                                  *,
                                  via_router: Router
                                  ) -> EmulatedSession:
        if not self._networking.is_emulated_nodes_attached(self, destination):
            raise RuntimeError("Attempt to create session between emulated nodes of different networkings")
        request, _, rreq_source_eph_priv = self._packet_generator.create_rreq(
            destination=destination.address,
            source_priv=self._private_signing,
        )
        via_router.network_tx.send(self.origin_address, request).result()
        destination.respond_to_request(request=request, via_router=via_router)
        response = self._find_response_for(request, self._networking.received)
        assert response, \
            "Got no response for RouteRequest"
        session = emulated_session(request, rreq_source_eph_priv, response, self._packet_generator)
        return session

    def respond_to_request(self, request: SignedRouteRequest, via_router: Router) -> None:
        response, _, _ = self._packet_generator.create_rrep(
            destination=address_from_full(request.payload.source),
            source_priv=self._private_signing,
            source_route_id=request.payload.source_route_id,
        )
        via_router.network_tx.send(self._origin_addr, response)

    def _find_response_for(self,
                           request: SignedRouteRequest,
                           recording: Sequence[tuple[Packet, ExternalAddress]],
                           ) -> SignedRouteResponse | None:
        request_triple = request.payload.info_triple
        responses = (packet for packet, _ in recording if isinstance(packet, SignedRouteResponse))
        for response in responses:
            if response.payload.request_info_triple == request_triple:
                return response
        return None


@dataclass(frozen=True)
class EmulatedSession:
    to_destination: tuple[Address, RouteID]
    from_source: tuple[Address, RouteID]
    cipher: ChaCha20Poly1305
    packet_generator: PacketGenerator
    _reverse_session: EmulatedSession | None = None

    @cached_property
    def reverse(self) -> EmulatedSession:
        return EmulatedSession(
            to_destination=self.from_source,
            from_source=self.to_destination,
            cipher=self.cipher,
            packet_generator=self.packet_generator,
            _reverse_session=self,
        )

    def create_outgoing_packet(self, payload: bytes) -> Data:
        nonce = token_bytes(CHACHA_NONCE_LENGTH)
        encrypted_payload = self.cipher.encrypt(nonce=nonce, data=payload, associated_data=None)
        packet = self.packet_generator.create_data(*self.to_destination, nonce, payload=encrypted_payload)
        return packet

    def decrypt_incoming_packet(self, packet: Data) -> bytes:
        assert (packet.destination, packet.route_id) == self.from_source, \
            "Attempt to decrypt data for other session"
        nonce = bytes(packet.chacha_nonce)
        encrypted_data = bytes(packet.payload)
        return self.cipher.decrypt(nonce=nonce, data=encrypted_data, associated_data=None)


def emulated_session(full_request: SignedRouteRequest,
                     request_eph: X25519PrivateKey,
                     full_response: SignedRouteResponse,
                     packet_generator: PacketGenerator,
                     ) -> EmulatedSession:
    request = full_request.payload
    response = full_response.payload
    assert request.source_route_id == response.source_route_id, \
        "Unmathed route id's in RouteRequest and RouteResponse"
    encryption_key = request_eph.exchange(full_response.payload.destination_eph)
    chacha = ChaCha20Poly1305(encryption_key)
    return EmulatedSession(
        to_destination=(address_from_full(response.source), response.destination_route_id),
        from_source=(address_from_full(request.source), request.source_route_id),
        cipher=chacha,
        packet_generator=packet_generator,
    )


class PacketsRecording(NamedTuple):
    from_router: Sequence[tuple[ExternalAddress, Packet]]
    from_frontend: Sequence[tuple[Address, bytes]]


class TracingTerminal(Terminal):

    def __init__(self, *, signing_key: Ed25519PrivateKey | None = None, router: Router, frontend: Frontend) -> None:
        signing_key = signing_key or Ed25519PrivateKey.generate()
        super().__init__(signing_key, router, frontend)
        self._rcv_from_router: list[tuple[ExternalAddress, Packet]] = []
        self._rcv_from_frontend: list[tuple[Address, bytes]] = []

    @property
    def received(self) -> PacketsRecording:
        return PacketsRecording(
            SequenceProxy(self._rcv_from_router),
            SequenceProxy(self._rcv_from_frontend),
        )

    def _incoming_packet_callback(self, origin: ExternalAddress, packet: Packet) -> Future[None]:
        self._rcv_from_router.append((origin, packet))
        return super()._incoming_packet_callback(origin, packet)

    def _outgoing_packet_callback(self, destination: Address, payload: bytes) -> Future[None]:
        self._rcv_from_frontend.append((destination, payload))
        return super()._outgoing_packet_callback(destination, payload)


class PacketGenerator:
    def create_rreq(self,
                    *,
                    destination: Address,
                    source_priv: Ed25519PrivateKey | None = None,
                    source_route_id: RouteID | None = None,
                    source_eph_priv: X25519PrivateKey | None = None,
                    max_hop_count: int = 64,
                    hop_count: int = 0,
                    ) -> tuple[SignedRouteRequest, Ed25519PrivateKey, X25519PrivateKey]:
        source_priv = source_priv or Ed25519PrivateKey.generate()
        source_eph_priv = source_eph_priv or X25519PrivateKey.generate()
        source_route_id = source_route_id or RouteID(randbits(32))
        request = RouteRequest(
            destination,
            FullAddress(source_priv.public_key()),
            source_route_id,
            source_eph_priv.public_key(),
            max_hop_count,
        )
        sign = source_priv.sign(bytes(request))
        return SignedRouteRequest(request, sign, hop_count), source_priv, source_eph_priv

    def create_rrep(self,
                    *,
                    destination: Address,
                    source_priv: Ed25519PrivateKey | None = None,
                    source_route_id: RouteID | None = None,
                    destination_route_id: RouteID | None = None,
                    destination_eph_priv: X25519PrivateKey | None = None,
                    max_hop_count: int = 64,
                    hop_count: int = 0,
                    ) -> tuple[SignedRouteResponse, Ed25519PrivateKey, X25519PrivateKey]:
        source_priv = source_priv or Ed25519PrivateKey.generate()
        source_route_id = source_route_id or RouteID(randbits(32))
        destination_route_id = destination_route_id or RouteID(randbits(32))
        destination_eph_priv = destination_eph_priv or X25519PrivateKey.generate()
        response = RouteResponse(
            destination,
            FullAddress(source_priv.public_key()),
            source_route_id,
            destination_route_id,
            destination_eph_priv.public_key(),
            max_hop_count,
        )
        sign = source_priv.sign(bytes(response))
        return SignedRouteResponse(response, sign, hop_count), source_priv, destination_eph_priv

    def create_data(self, destination: Address, route_id: RouteID, chacha_nonce: bytes, payload: bytes) -> Data:
        return Data(destination, route_id, chacha_nonce, payload=payload)

    def create_rerr(self, route_destination: Address, route_id: RouteID) -> RouteError:
        return RouteError(route_destination, route_id)


Time = float


class ScheduleItem(NamedTuple, Generic[*Args]):
    call_at: Time
    callback: Callback[*Args]
    args: tuple[*Args]


class Scheduled(ScheduleHandle):
    def __init__(self, timer: ThreadedScheduler, plan_item: ScheduleItem) -> None:
        super().__init__()
        self._timer = timer
        self._plan_item = plan_item
        self._cancelled = False

    @property
    def schedule_item(self) -> ScheduleItem:
        return self._plan_item

    def cancel(self) -> None:
        if self._cancelled:
            return
        self._cancelled = True
        self._timer.cancel(self)
        return super().cancel()

    def cancelled(self) -> bool:
        return self._cancelled


class ThreadedScheduler(Scheduler):
    def __init__(self) -> None:
        self._scedule: deque[ScheduleItem] = deque()
        self._has_items = Event()
        self._working = Event()
        self._running: set[Thread] = set()
        self._thread: Thread | None = None

    @property
    def schedule(self) -> Sequence[ScheduleItem]:
        return SequenceProxy(self._scedule)

    @property
    def working(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and self._working.is_set()

    def launch(self) -> None:
        if self._thread:
            raise RuntimeError("Already launched")
        self._thread = Thread(target=self._process_schedule)
        self._working.set()
        self._thread.start()

    def stop(self, *, drop_schedule: bool = True) -> None:
        if self._thread is None:
            return
        self._working.clear()
        self._reschedule()
        self._thread.join()
        if drop_schedule:
            self._scedule.clear()

    def call_later(self, delay: float, callback: Callback[*Args], *args: *Args) -> Scheduled:
        call_at = time.time() + delay
        plan_item: ScheduleItem = ScheduleItem(call_at, callback, args)
        bisect.insort(self._scedule, plan_item, key=lambda element: element.call_at)
        self._reschedule()
        return Scheduled(self, plan_item)

    def cancel(self, handle: Scheduled) -> None:
        need_reschedule = bool(self._scedule and self._scedule[0] is handle.schedule_item)
        self._scedule.remove(handle.schedule_item)
        if need_reschedule:
            self._reschedule()

    def _reschedule(self) -> None:
        if not self._scedule:
            return
        self._has_items.set()

    def _process_schedule(self) -> None:
        delay: float | None = None
        while self._working.is_set():
            self._has_items.wait(delay)
            self._has_items.clear()
            while self._scedule:
                next_planned = self._scedule[0]
                now = time.time()
                if next_planned.call_at > now:
                    break
                item = self._scedule.popleft()
                self._run_scheduled(item)
            delay = None
            if self._scedule:
                next_planned = self._scedule[0]
                now = time.time()
                if now < next_planned.call_at:
                    delay = next_planned.call_at - now

    def _run_scheduled(self, item: ScheduleItem[*Args]) -> None:
        def wrap(fn: Callback[*Args], args: tuple[*Args]) -> None:
            try:
                fn(*args)
            finally:
                self._running.remove(thread)

        thread = Thread(target=wrap, args=(item.callback, item.args), name=f"Scheduled-{item.callback}")
        self._running.add(thread)
        thread.start()


class SchedulerProxy(Scheduler):
    def __init__(self, scheduler: ThreadedScheduler) -> None:
        super().__init__()
        self._scheduler = scheduler

    @property
    def schedule(self) -> Sequence[ScheduleItem]:
        return self._scheduler.schedule

    def call_later(self, delay: float, callback: Callback[*Args], *args: *Args) -> ScheduleHandle:
        return self._scheduler.call_later(delay, callback, *args)

    def cancel(self, handle: Scheduled) -> None:
        return self._scheduler.cancel(handle)


@contextmanager
def threaded_scheduler() -> Generator[SchedulerProxy, Any, None]:  # type: ignore
    scheduler = ThreadedScheduler()
    scheduler.launch()
    yield SchedulerProxy(scheduler)
    scheduler.stop(drop_schedule=True)
