from __future__ import annotations

import logging
from typing import Callable, Protocol, TypeAlias

from .addresses import Address, ExternalAddress, FullAddress, address_from_full
from .core import Frontend, NetworkingProtocol, Router, Terminal
from .crypto import Ed25519PrivateKey
from .interactors import FrontendRX, NetworkRX
from .packets import QORPPacket
from .utils.futures import Future, ConstFuture
from .utils.timer import Scheduler


log = logging.getLogger(__name__)

Packet: TypeAlias = QORPPacket


class DefaultNetworkingRX(NetworkRX):
    def __init__(self, networking: DefaultNetworking, router: Router) -> None:
        super().__init__()

    def send(self, destination: ExternalAddress, packet: Packet) -> Future[None]:
        return ConstFuture(result=None)

    def propagate(self, packet: Packet, exclude: ExternalAddress) -> Future[None]:
        return ConstFuture(result=None)


class DefaultNetworking(NetworkingProtocol):
    def __init__(self, identity_key: Ed25519PrivateKey) -> None:
        super().__init__()
        self._identity_key = identity_key

    @property
    def identity_key(self) -> Ed25519PrivateKey:
        return self._identity_key

    def attach(self, router: Router) -> NetworkRX:
        return DefaultNetworkingRX(self, router)


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


class RouterFactory(Protocol):
    def __call__(self, network: NetworkingProtocol, *, scheduler: Scheduler) -> Router:
        pass


class QORPNode:
    def __init__(self,
                 networking: NetworkingProtocol | None = None,
                 identity_key: Ed25519PrivateKey | None = None,
                 router_factory: RouterFactory = Router,
                 frontend: Frontend | None = None,
                 *,
                 scheduler: Scheduler,
                 ) -> None:
        if networking is not None:
            self._networking = networking
            self._identity_key = networking.identity_key
        else:
            self._identity_key = identity_key or Ed25519PrivateKey.generate()
            self._networking = DefaultNetworking(self._identity_key)
        self._router = router_factory(self._networking, scheduler=scheduler)
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
