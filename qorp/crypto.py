from __future__ import annotations

from typing import Protocol, Self, TypeVar
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import Hash, SHA3_256

from cryptography.hazmat.primitives import serialization


CHACHA_NONCE_LENGTH = 12

SupportedEncoding = TypeVar("SupportedEncoding", contravariant=True)
SupportedEncryption = TypeVar("SupportedEncryption", contravariant=True)
SupportedFormat = TypeVar("SupportedFormat", contravariant=True)
SigningPrivateKeyT = TypeVar("SigningPrivateKeyT", bound="SigningPrivateKey")
SigningPublicKeyT = TypeVar("SigningPublicKeyT", bound="SigningPublicKey", covariant=True)
KExPrivateKeyT = TypeVar("KExPrivateKeyT", bound="KExPrivateKey")
KExPublicKeyT = TypeVar("KExPublicKeyT", bound="KExPublicKey")


class SigningPrivateKey(Protocol[SigningPublicKeyT, SupportedEncoding, SupportedFormat, SupportedEncryption]):
    @classmethod
    def from_private_bytes(cls: type[Self], data: bytes) -> Self:
        pass

    @classmethod
    def generate(cls: type[Self]) -> Self:
        pass

    def private_bytes(self,
                      encoding: SupportedEncoding,
                      format: SupportedFormat,
                      encryption_algorithm: SupportedEncryption,
                      ) -> bytes:
        pass

    def public_key(self) -> SigningPublicKeyT:
        pass

    def sign(self, data: bytes) -> bytes:
        pass


class SigningPublicKey(Protocol[SupportedEncoding, SupportedFormat]):
    @classmethod
    def from_public_bytes(cls: type[Self], data: bytes) -> Self:
        pass

    def public_bytes(self, encoding: SupportedEncoding, format: SupportedFormat) -> bytes:
        pass

    def verify(self, signature: bytes, data: bytes) -> None:
        pass


class KExPrivateKey(Protocol[KExPublicKeyT, SupportedEncoding, SupportedFormat, SupportedEncryption]):
    def exchange(self, peer_public_key: KExPublicKeyT) -> bytes:
        pass

    @classmethod
    def from_private_bytes(cls: type[Self], data: bytes) -> Self:
        pass

    @classmethod
    def generate(cls: type[Self]) -> Self:
        pass

    def private_bytes(self,
                      encoding: SupportedEncoding,
                      format: SupportedFormat,
                      encryption_algorithm: SupportedEncryption,
                      ) -> bytes:
        pass

    def public_key(self) -> KExPublicKeyT:
        pass


class KExPublicKey(Protocol[SupportedEncoding, SupportedFormat]):
    @classmethod
    def from_public_bytes(cls: type[Self], data: bytes) -> Self:
        pass

    def public_bytes(self, encoding: SupportedEncoding, format: SupportedFormat) -> bytes:
        pass


class AEADCipher(Protocol):
    def decrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None) -> bytes:
        pass

    def encrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None) -> bytes:
        pass

    @classmethod
    def generate_key(cls) -> bytes:
        pass


class HashFunction(Protocol):
    def update(self, data: bytes) -> None:
        pass

    def finalize(self) -> bytes:
        pass


if TYPE_CHECKING:
    def sig_priv(key: SigningPrivateKey[SigningPublicKeyT, SupportedEncoding, SupportedFormat, SupportedEncryption],
                 encoding: SupportedEncoding, format: SupportedFormat, encryption: SupportedEncryption
                 ) -> None: pass
    sig_priv(Ed25519PrivateKey.generate(),
             serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())

    def sig_pub(key: SigningPublicKey[SupportedEncoding, SupportedFormat],
                encoding: SupportedEncoding, format: SupportedFormat) -> None: pass
    sig_pub(Ed25519PublicKey.from_public_bytes(b''), serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def kex_priv(key: KExPrivateKey[KExPublicKeyT, SupportedEncoding, SupportedFormat, SupportedEncryption],
                 encoding: SupportedEncoding, format: SupportedFormat, encryption: SupportedEncryption
                 ) -> None: pass
    kex_priv(X25519PrivateKey.generate(),
             serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())

    def kex_pub(key: KExPublicKey[SupportedEncoding, SupportedFormat],
                encoding: SupportedEncoding, format: SupportedFormat) -> None: pass
    kex_pub(X25519PublicKey.from_public_bytes(b''), serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def aead(cipher: AEADCipher) -> None: pass
    aead(ChaCha20Poly1305(b''))

    def hash_fn(hash_function: HashFunction) -> None: pass
    hash_fn(Hash(SHA3_256()))
