from __future__ import annotations

from ctypes import BigEndianStructure, c_char, c_ubyte, c_uint16, c_uint32, c_uint8, Array
from functools import lru_cache
from typing import ClassVar, NamedTuple, Self, TypeVar
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ctypes import _CData

from qorp.addresses import Address, FullAddress, address_from_full, format_bytes
from qorp.crypto import Ed25519PrivateKey, Ed25519PublicKey, X25519PublicKey
from qorp.crypto import Encoding, PublicFormat, CHACHA_NONCE_LENGTH
from qorp.crypto import InvalidSignature
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

    def __init__(self,
                 destination: Address,
                 source: FullAddress,
                 source_route_id: RouteID,
                 source_eph: X25519PublicKey,
                 max_hop_count: int,
                 ) -> None:
        destination_raw = RawAddress.from_buffer_copy(destination)
        source_raw = RawFullAddress.from_buffer_copy(source.public_bytes(Encoding.Raw, PublicFormat.Raw))
        source_eph_raw = RawPubKey.from_buffer_copy(source_eph.public_bytes(Encoding.Raw, PublicFormat.Raw))
        return super().__init__(
            destination_raw=destination_raw,
            source_raw=source_raw,
            source_route_id=source_route_id,
            source_eph_raw=source_eph_raw,
            max_hop_count=max_hop_count,
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

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"destination={format_bytes(self.destination)}, "
            f"source={format_bytes(bytes(self.source_raw))}, "
            f"source_route_id={self.source_route_id}, "
            f"max_hop_count={self.max_hop_count}"
            ")"
        )

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"destination={format_bytes(self.destination)}, "
            f"source={format_bytes(bytes(self.source_raw))}, "
            f"source_route_id={self.source_route_id}, "
            f"max_hop_count={self.max_hop_count}"
            ")"
        )


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

    def __init__(self, payload: RouteRequest, sign: bytes, hop_count: int) -> None:
        super().__init__(payload=payload, sign=RawSign.from_buffer_copy(sign), hop_count=hop_count)

    def verify(self) -> bool:
        try:
            self.payload.source.verify(bytes(self.sign), bytes(self.payload))
        except InvalidSignature:
            return False
        return True


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

    def __init__(self,
                 destination: Address, source: FullAddress,
                 source_route_id: RouteID, destination_route_id: RouteID,
                 destination_eph: X25519PublicKey,
                 max_hop_count: int,
                 ) -> None:
        return super().__init__(
            destination_raw=RawAddress.from_buffer_copy(destination),
            source_raw=RawFullAddress.from_buffer_copy(source.public_bytes(Encoding.Raw, PublicFormat.Raw)),
            source_route_id=source_route_id,
            destination_route_id=destination_route_id,
            destination_eph_raw=RawPubKey.from_buffer_copy(destination_eph.public_bytes(Encoding.Raw, PublicFormat.Raw)),
            max_hop_count=max_hop_count,
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

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"destination={format_bytes(self.destination)}, "
            f"source={format_bytes(bytes(self.source_raw))}, "
            f"source_route_id={self.source_route_id}, "
            f"destination_route_id={self.destination_route_id}, "
            f"max_hop_count={self.max_hop_count}"
            ")"
        )

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"destination={format_bytes(self.destination)}, "
            f"source={format_bytes(bytes(self.source_raw))}, "
            f"source_route_id={self.source_route_id}, "
            f"destination_route_id={self.destination_route_id}, "
            f"max_hop_count={self.max_hop_count}"
            ")"
        )


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

    def __init__(self, payload: RouteResponse, sign: bytes, hop_count: int) -> None:
        super().__init__(payload=payload, sign=RawSign.from_buffer_copy(sign), hop_count=hop_count)

    def verify(self) -> bool:
        try:
            self.payload.source.verify(bytes(self.sign), bytes(self.payload))
        except InvalidSignature:
            return False
        return True


class RouteError(PacketBase):
    route_destination: Address
    route_id: RouteID

    __match_args__ = ("route_destination", "route_id")

    def __init__(self,
                 route_destination: Address,
                 route_id: RouteID
                 ) -> None:
        return super().__init__(route_destination=route_destination, route_id=route_id)

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"route_destination={format_bytes(self.route_destination)}, "
            f"route_id={self.route_id}"
            ")"
        )

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"route_destination={format_bytes(self.route_destination)}, "
            f"route_id={self.route_id}"
            ")"
        )


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

    def __new__(cls: type[Self], *args, **kwargs) -> Self:  # type: ignore
        if cls is Data:
            cls = cls.for_length(len(kwargs.get('payload')))  # type: ignore
        return super().__new__(cls, *args, **kwargs)

    def __init__(self,
                 destination: Address,
                 route_id: RouteID,
                 chacha_nonce: bytes,
                 *,
                 payload: bytes,
                 ) -> None:
        payload_length = len(payload)
        return super().__init__(
            destination_raw=RawAddress.from_buffer_copy(destination),
            route_id=route_id,
            chacha_nonce=RawNonce.from_buffer_copy(chacha_nonce),
            payload_length=payload_length,
            payload=(c_ubyte*payload_length).from_buffer_copy(payload),
        )

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

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"destination={format_bytes(self.destination)}, "
            f"route_id={self.route_id}, "
            f"payload=b'...'({self.payload_length} bytes)"
            ")"
        )

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"destination={format_bytes(self.destination)}, "
            f"route_id={self.route_id}, "
            f"payload=b'...'({self.payload_length} bytes)"
            ")"
        )


QORPPacket = Data | SignedRouteRequest | SignedRouteResponse | RouteError
