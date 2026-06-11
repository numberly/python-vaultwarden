import dataclasses
import typing
from typing import Any, TypeAlias, cast
from uuid import UUID

from Crypto.PublicKey import RSA
from pydantic import (
    SerializationInfo,
    SerializerFunctionWrapHandler,
    ValidationInfo,
    ValidatorFunctionWrapHandler,
    WrapSerializer,
    WrapValidator,
)
from typing_extensions import Annotated

from vaultwarden.utils.crypto import AsymmetricCipher, SymmetricCipher

if typing.TYPE_CHECKING:
    from vaultwarden.clients.bitwarden import BitwardenAPIClient


def decode_string(
    value: Any, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
) -> str:
    ctx = cast(CryptoContext, info.context)
    return handler(SymmetricCipher.decode(value, ctx.stack[-1]))


def encode_string(
    value: str, handler: SerializerFunctionWrapHandler, info: SerializationInfo
) -> str:
    ctx = cast(CryptoContext, info.context)
    return handler(SymmetricCipher.encode(value.encode(), ctx.stack[-1]))


SecretString = Annotated[
    str, WrapValidator(decode_string), WrapSerializer(encode_string)
]
"""
Symmetric encoded string value
"""


def decode_bytes(
    value: str, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
) -> bytes:
    ctx = cast(CryptoContext, info.context)
    return handler(SymmetricCipher.decode(value, ctx.stack[-1]))


def encode_bytes(
    value: Any, handler: SerializerFunctionWrapHandler, info: SerializationInfo
) -> bytes:
    ctx = cast(CryptoContext, info.context)
    return handler(SymmetricCipher.encode(value, ctx.stack[-1]))


SecretBytes = Annotated[
    bytes, WrapValidator(decode_bytes), WrapSerializer(encode_bytes)
]
"""
Symmetric encoded bytes value
"""


def decode_rsa(
    value: str, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
) -> RSA.RsaKey:
    ctx = cast(CryptoContext, info.context)
    return handler(RSA.importKey(SymmetricCipher.decode(value, ctx.stack[-1])))


def encode_rsa(
    value: RSA.RsaKey,
    handler: SerializerFunctionWrapHandler,
    info: SerializationInfo,
) -> bytes:
    ctx = cast(CryptoContext, info.context)
    return handler(
        SymmetricCipher.encode(value.exportKey("DER", pkcs=8), ctx.stack[-1])
    )


SecretRSA = Annotated[
    RSA.RsaKey, WrapValidator(decode_rsa), WrapSerializer(encode_rsa)
]
"""
Symmetric encoded RSA key
"""


def decode_org_key(
    value: str, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
) -> bytes:
    ctx = cast(CryptoContext, info.context)
    return handler(AsymmetricCipher.decode(value, ctx.stack[-1]))


def encode_org_key(
    value: bytes,
    handler: SerializerFunctionWrapHandler,
    info: SerializationInfo,
) -> str:
    ctx = cast(CryptoContext, info.context)
    return handler(AsymmetricCipher.encode(value, ctx.stack[-1]))


SecretOrganizationKey = Annotated[
    bytes, WrapValidator(decode_org_key), WrapSerializer(encode_org_key)
]
"""
Asymmetric encoded Key

* key is not added to cctx
* encoding uses the seconds last key in cctx
"""


def decode_key(
    value: str, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
) -> bytes:
    ctx = cast(CryptoContext, info.context)
    return handler(SymmetricCipher.decode(value, ctx.stack[-2]))


def encode_key(
    value: Any, handler: SerializerFunctionWrapHandler, info: SerializationInfo
) -> bytes:
    ctx = cast(CryptoContext, info.context)
    return handler(SymmetricCipher.encode(value, ctx.stack[-2]))


SecretKey = Annotated[
    bytes, WrapValidator(decode_key), WrapSerializer(encode_key)
]
"""
Symmetric encoded Key

* the Key is added to cctx by ser_set_key / val_set_key of the model
* en/decoding uses the [-2] key in cctx
"""

CryptoKey: TypeAlias = RSA.RsaKey | bytes


@dataclasses.dataclass(frozen=True)
class CryptoContext:
    client: "BitwardenAPIClient"
    parent_id: UUID | None = None
    stack: list[CryptoKey] = dataclasses.field(default_factory=list)

    def push(self, v: CryptoKey) -> None:
        return self.stack.append(v)

    def pop(self) -> CryptoKey:
        return self.stack.pop()
