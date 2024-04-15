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
