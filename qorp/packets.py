from __future__ import annotations

from ctypes import BigEndianStructure, c_char, c_uint16, c_uint32, c_uint8
from functools import lru_cache
from typing import NamedTuple, TypeVar
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ctypes import _CData

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from qorp.addresses import Address, FullAddress, address_from_full
from qorp.crypto import Ed25519PrivateKey
from qorp._types import RouteID, Buffer


AnyPacket = TypeVar("AnyPacket", bound="PacketBase")


class RequestInfoTriple(NamedTuple):
    source: Address
    destination: Address
    route_id: RouteID


class PacketBase(BigEndianStructure):
    _fields_: list[tuple[str, type[_CData]] | tuple[str, type[_CData], int]]

    @classmethod
    def from_bytes(cls: type[AnyPacket], raw: Buffer) -> AnyPacket:
        return cls.from_buffer_copy(raw)


class UnsignedRouteRequest(BigEndianStructure):
    _fields_ = [
        ("destination_raw", c_char*16),
        ("source_raw", c_char*32),
        ("request_id", c_uint32),
        ("source_eph_raw", c_char*32),
        ("max_hop_count", c_uint8),
    ]


class RouteRequest(BigEndianStructure):
    _fields_ = [
        ("destination_raw", c_char*16),
        ("source_raw", c_char*32),
        ("source_route_id", c_uint32),
        ("source_eph_raw", c_char*32),
        ("max_hop_count", c_uint8),
    ]
    destination_raw: bytes
    source_raw: bytes
    source_route_id: RouteID
    source_eph_raw: bytes
    max_hop_count: int

    @property
    def destination(self) -> Address:
        return Address(self.destination_raw)

    @property
    def source(self) -> FullAddress:
        signing_key = Ed25519PublicKey.from_public_bytes(self.source_raw)
        return FullAddress(signing_key)

    @property
    def source_eph(self) -> X25519PublicKey:
        return X25519PublicKey.from_public_bytes(self.source_eph_raw)

    @property
    def info_triple(self) -> RequestInfoTriple:
        source = address_from_full(self.source)
        return RequestInfoTriple(source, self.destination, self.source_route_id)

    def sign(self, signing_key: Ed25519PrivateKey) -> SignedRouteRequest:
        sign = signing_key.sign(bytes(self))
        return SignedRouteRequest(payload=self, sign=sign, hop_count=0)


class SignedRouteRequest(PacketBase):
    _fields_ = [
        ("payload", RouteRequest),
        ("sign", c_char*64),
        ("hop_count", c_uint8),
    ]
    payload: RouteRequest
    sign: bytes
    hop_count: int


class RouteResponse(BigEndianStructure):
    _fields_ = [
        ("destination_raw", c_char*16),
        ("source_raw", c_char*32),
        ("source_route_id", c_uint32),
        ("destination_route_id", c_uint32),
        ("destination_eph_raw", c_char*32),
        ("sign", c_char*64),
    ]
    destination_raw: bytes
    source_raw: bytes
    source_route_id: RouteID
    destination_route_id: RouteID
    destination_eph_raw: bytes
    max_hop_count: int

    @property
    def destination(self) -> Address:
        return Address(self.destination_raw)

    @property
    def source(self) -> FullAddress:
        signing_key = Ed25519PublicKey.from_public_bytes(self.source_raw)
        return FullAddress(signing_key)

    @property
    def destination_eph(self) -> X25519PublicKey:
        return X25519PublicKey.from_public_bytes(self.destination_eph_raw)

    @property
    def request_info_triple(self) -> RequestInfoTriple:
        source = address_from_full(self.source)
        return RequestInfoTriple(self.destination, source, self.source_route_id)

    def sign(self, signing_key: Ed25519PrivateKey) -> SignedRouteResponse:
        sign = signing_key.sign(bytes(self))
        return SignedRouteResponse(payload=self, sign=sign, hop_count=0)


class SignedRouteResponse(PacketBase):
    _fields_ = [
        ("payload", RouteResponse),
        ("sign", c_char*64),
        ("hop_count", c_uint8),
    ]
    payload: RouteResponse
    sign: bytes
    hop_count: int


class RouteError(PacketBase):
    route_destination: Address
    route_id: RouteID


class RouteOptimization(PacketBase):
    pass


class DataHeader(PacketBase):
    _fields_ = [
        ("session_id", c_uint32),
        ("chacha_nonce", c_char*12),
        ("length", c_uint16),
    ]
    session_id: int
    chacha_nonce: bytes
    length: int


class Data(PacketBase):
    _fields_ = [
        ("destination_raw", c_char*16),
        ("route_id", c_uint32),
        ("chacha_nonce", c_char*12),
        ("length", c_uint16),
    ]
    destination_raw: bytes
    route_id: RouteID
    chacha_nonce: bytes
    payload_length: int
    payload: bytes

    @property
    def destination(self) -> Address:
        return Address(self.destination_raw)

    @classmethod
    @lru_cache
    def for_length(cls, len: int) -> type[Data]:
        class SpecificLengthData(Data):
            _fields_ = [
                ("payload", c_char*len)
            ]

        return SpecificLengthData


QORPPacket = Data | SignedRouteRequest | SignedRouteResponse | RouteError
