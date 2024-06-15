from dataclasses import dataclass
from functools import cached_property
from typing import NewType

from qorp.crypto import Ed25519PublicKey
from qorp.crypto import Hash, SHA3_256
from qorp.crypto import Encoding, PublicFormat


FullAddress = NewType("FullAddress", Ed25519PublicKey)
ExternalAddress = NewType("ExternalAddress", Ed25519PublicKey)
Address = NewType("Address", bytes)


def address_from_full(full_addr: FullAddress) -> Address:
    return address_from_key(full_addr)


def address_from_key(pubkey: Ed25519PublicKey) -> Address:
    pubkey_bytes = pubkey.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    hash = Hash(SHA3_256())
    hash.update(pubkey_bytes)
    key_hash = hash.finalize()
    return Address(key_hash[:16])


def format_bytes(b: bytes) -> str:
    return b.hex(sep=":", bytes_per_sep=4)


@dataclass(frozen=True)
class PubkeyView:
    pubkey: Ed25519PublicKey

    @cached_property
    def _as_str(self) -> str:
        return format_bytes(address_from_key(self.pubkey))

    def __str__(self) -> str:
        return self._as_str


@dataclass(frozen=True)
class BytesView:
    data: bytes

    @cached_property
    def _as_str(self) -> str:
        return format_bytes(self.data)

    def __str__(self) -> str:
        return self._as_str
