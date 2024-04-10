from typing import NewType

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.hashes import Hash, SHA3_256
from cryptography.hazmat.primitives import serialization


FullAddress = NewType("FullAddress", Ed25519PublicKey)
ExternalAddress = NewType("ExternalAddress", Ed25519PublicKey)
Address = NewType("Address", bytes)


def address_from_full(full_addr: FullAddress) -> Address:
    full_addr_bytes = full_addr.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    hash = Hash(SHA3_256())
    hash.update(full_addr_bytes)
    key_hash = hash.finalize()
    return Address(key_hash[:16])
