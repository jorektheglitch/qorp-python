from __future__ import annotations

from ctypes import BigEndianStructure, c_char, c_ubyte, c_uint16, c_uint32, c_uint8, Array
from functools import lru_cache
from typing import ClassVar, NamedTuple, TypeVar
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ctypes import _CData

from qorp.addresses import Address, FullAddress, address_from_full
from qorp.crypto import Ed25519PrivateKey, Ed25519PublicKey, X25519PublicKey
from qorp.crypto import CHACHA_NONCE_LENGTH
from qorp._types import RouteID, Buffer


AnyPacket = TypeVar("AnyPacket", bound="PacketBase")
RawAddress = c_ubyte*16
RawFullAddress = RawPubKey = c_ubyte*32
RawNonce = c_ubyte*CHACHA_NONCE_LENGTH
RawSign = c_ubyte*64


class RequestInfoTriple(NamedTuple):
    source: Address
    destination: Address
    route_id: RouteID


class Structure(BigEndianStructure):
    _pack_ = 1
    _fields_: ClassVar[list[tuple[str, type[_CData]] | tuple[str, type[_CData], int]]]

    def __hash__(self) -> int:
        return int.from_bytes(self)


class PacketBase(Structure):

    @classmethod
    def from_bytes(cls: type[AnyPacket], raw: Buffer) -> AnyPacket:
        return cls.from_buffer_copy(raw)


class RouteRequest(Structure):
    _fields_ = [
        ("destination_raw", RawAddress),
        ("source_raw", RawFullAddress),
        ("source_route_id", c_uint32),
        ("source_eph_raw", RawPubKey),
        ("max_hop_count", c_uint8),
    ]
    destination_raw: Array[c_ubyte]
    source_raw: Array[c_ubyte]
    source_route_id: RouteID
    source_eph_raw: Array[c_ubyte]
    max_hop_count: int

    __match_args__ = (
        "destination", "source", "source_route_id", "source_eph", "max_hop_count"
    )

    @property
    def destination(self) -> Address:
        return Address(bytes(self.destination_raw))

    @property
    def source(self) -> FullAddress:
        signing_key = Ed25519PublicKey.from_public_bytes(bytes(self.source_raw))
        return FullAddress(signing_key)

    @property
    def source_eph(self) -> X25519PublicKey:
        return X25519PublicKey.from_public_bytes(bytes(self.source_eph_raw))

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
        ("sign", RawSign),
        ("hop_count", c_uint8),
    ]
    payload: RouteRequest
    sign: Array[c_ubyte]
    hop_count: int

    __match_args__ = ("payload", "sign", "hop_count")


class RouteResponse(Structure):
    _fields_ = [
        ("destination_raw", RawAddress),
        ("source_raw", RawFullAddress),
        ("source_route_id", c_uint32),
        ("destination_route_id", c_uint32),
        ("destination_eph_raw", RawPubKey),
        ("max_hop_count", c_uint8),
    ]
    destination_raw: Array[c_ubyte]
    source_raw: Array[c_ubyte]
    source_route_id: RouteID
    destination_route_id: RouteID
    destination_eph_raw: Array[c_ubyte]
    max_hop_count: int

    __match_args__ = (
        "destination", "source", "source_route_id", "destination_route_id", "destination_eph", "max_hop_count"
    )

    @property
    def destination(self) -> Address:
        return Address(bytes(self.destination_raw))

    @property
    def source(self) -> FullAddress:
        signing_key = Ed25519PublicKey.from_public_bytes(bytes(self.source_raw))
        return FullAddress(signing_key)

    @property
    def destination_eph(self) -> X25519PublicKey:
        return X25519PublicKey.from_public_bytes(bytes(self.destination_eph_raw))

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
        ("sign", RawSign),
        ("hop_count", c_uint8),
    ]
    payload: RouteResponse
    sign: Array[c_ubyte]
    hop_count: int

    __match_args__ = ("payload", "sign", "hop_count")


class RouteError(PacketBase):
    route_destination: Address
    route_id: RouteID

    __match_args__ = ("route_destination", "route_id")


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
        ("destination_raw", RawAddress),
        ("route_id", c_uint32),
        ("chacha_nonce", RawNonce),
        ("length", c_uint16),
    ]
    destination_raw: Array[c_ubyte]
    route_id: RouteID
    chacha_nonce: Array[c_ubyte]
    payload_length: int
    payload: Array[c_ubyte]

    __match_args__ = ("destination", "route_id", "chacha_nonce", "payload")

    @property
    def destination(self) -> Address:
        return Address(bytes(self.destination_raw))

    @classmethod
    @lru_cache
    def for_length(cls, len: int) -> type[Data]:
        class SpecificLengthData(Data):
            _fields_ = [
                ("payload", c_ubyte*len)
            ]

        return SpecificLengthData


QORPPacket = Data | SignedRouteRequest | SignedRouteResponse | RouteError
