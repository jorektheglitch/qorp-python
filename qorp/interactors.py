from abc import ABC, abstractmethod

from qorp.addresses import Address, ExternalAddress
from qorp.packets import QORPPacket
from qorp.utils.futures import Future


class NetworkRX(ABC):
    @abstractmethod
    def send(self, destination: ExternalAddress, packet: QORPPacket) -> Future[None]:
        pass

    @abstractmethod
    def propagate(self, packet: QORPPacket, exclude: ExternalAddress) -> Future[None]:
        pass


class NetworkTX(ABC):
    @abstractmethod
    def send(self, origin: ExternalAddress, packet: QORPPacket) -> Future[None]:
        pass


class RouterRX(ABC):
    @abstractmethod
    def send(self, packet: QORPPacket) -> Future[None]:
        pass


class RouterTX(ABC):
    @abstractmethod
    def send(self, origin: ExternalAddress, packet: QORPPacket) -> Future[None]:
        pass


class FrontendRX(ABC):
    @abstractmethod
    def send(self, source: Address, payload: bytes) -> Future[None]:
        pass


class FrontendTX(ABC):
    @abstractmethod
    def send(self, destination: Address, payload: bytes) -> Future[None]:
        pass
