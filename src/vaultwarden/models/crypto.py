from typing import Annotated, Any, cast

from Crypto.PublicKey import RSA
from pydantic import (
    SerializationInfo,
    SerializerFunctionWrapHandler,
    ValidationInfo,
    ValidatorFunctionWrapHandler,
    WrapSerializer,
    WrapValidator,
)

from vaultwarden.utils.crypto import AsymmetricCipher, SymmetricCipher


def decode_string(
    value: Any, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
) -> str:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    return handler(SymmetricCipher.decode(value, keys[-1]))


def encode_string(
    value: str, handler: SerializerFunctionWrapHandler, info: SerializationInfo
) -> str:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    if keys:
        return handler(SymmetricCipher.encode(value.encode(), keys[-1]))
    raise ValueError("No key found")


SecretString = Annotated[
    str, WrapValidator(decode_string), WrapSerializer(encode_string)
]
"""
Symmetric encoded string value
"""


def decode_bytes(
    value: str, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
) -> bytes:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    return handler(SymmetricCipher.decode(value, keys[-1]))


def encode_bytes(
    value: Any, handler: SerializerFunctionWrapHandler, info: SerializationInfo
) -> bytes:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    return handler(SymmetricCipher.encode(value, keys[-1]))


SecretBytes = Annotated[
    bytes, WrapValidator(decode_bytes), WrapSerializer(encode_bytes)
]
"""
Symmetric encoded bytes value
"""


def decode_rsa(
    value: str, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
) -> RSA.RsaKey:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    return handler(RSA.importKey(SymmetricCipher.decode(value, keys[-1])))


def encode_rsa(
    value: RSA.RsaKey,
    handler: SerializerFunctionWrapHandler,
    info: SerializationInfo,
) -> bytes:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    return handler(
        SymmetricCipher.encode(value.exportKey("DER", pkcs=8), keys[-1])
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
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    return handler(AsymmetricCipher.decode(value, keys[-1]))


def encode_org_key(
    value: bytes,
    handler: SerializerFunctionWrapHandler,
    info: SerializationInfo,
) -> str:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    return handler(AsymmetricCipher.encode(value, keys[-1]))


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
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    return handler(SymmetricCipher.decode(value, keys[-2]))


def encode_key(
    value: Any, handler: SerializerFunctionWrapHandler, info: SerializationInfo
) -> bytes:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    return handler(SymmetricCipher.encode(value, keys[-2]))


SecretKey = Annotated[
    bytes, WrapValidator(decode_key), WrapSerializer(encode_key)
]
"""
Symmetric encoded Key

* the Key is added to cctx by ser_set_key / val_set_key of the model
* en/decoding uses the [-2] key in cctx
"""
