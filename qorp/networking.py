from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from types import MappingProxyType
from typing import TypeAlias

from qorp.interactors import NetworkRX
from qorp.core import Router


class Proto(Enum):
    UDP = 'UDP'
    QUIC = 'QUIC'
    WebSocket = 'WS'


Port: TypeAlias = int
PeerAddress: TypeAlias = tuple[Proto, IPv4Address | IPv6Address, Port]


@dataclass
class PeerInfo:
    pass


@dataclass
class ListenerInfo:
    pass


class Networking(ABC):

    @abstractmethod
    def attach(self, router: Router) -> NetworkRX:
        pass

    @property
    @abstractmethod
    def peers(self) -> MappingProxyType[PeerAddress, PeerInfo]:
        pass

    @property
    @abstractmethod
    def listeners(self) -> MappingProxyType[PeerAddress, PeerInfo]:
        pass

    @abstractmethod
    def add_peer(self, address: PeerAddress) -> None:
        pass

    @abstractmethod
    def add_listener(self, address: PeerAddress) -> None:
        pass

    @abstractmethod
    def remove_peer(self, address: PeerAddress) -> None:
        pass

    @abstractmethod
    def remove_listener(self, address: PeerAddress) -> None:
        pass

    @abstractmethod
    def launch(self) -> None:
        pass

    @abstractmethod
    def stop(self) -> None:
        pass
