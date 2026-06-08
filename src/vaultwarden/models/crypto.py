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


def decode_org_key(
    value: str, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
) -> bytes:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    for key in keys[::-1]:
        if not isinstance(key, RSA.RsaKey):
            continue
        try:
            return handler(AsymmetricCipher.decode(value, key))
        except Exception as e:
            print(e)
            continue
    raise ValueError("No key found")


def encode_org_key(
    value: bytes,
    handler: SerializerFunctionWrapHandler,
    info: SerializationInfo,
) -> str:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    if keys:
        return handler(AsymmetricCipher.encode(value, keys[-2]))
    raise ValueError("No key found")


SecretOrganizationKey = Annotated[
    bytes, WrapValidator(decode_org_key), WrapSerializer(encode_org_key)
]


def decode_string(
    value: Any, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
) -> str:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    for key in keys[::-1]:
        try:
            return handler(SymmetricCipher.decode(value, key))
        except Exception as e:
            print(e)
            continue
    raise ValueError("No key found")


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


def decode_cipher_key(
    value: str, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
) -> bytes:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    for key in keys[-2::-1]:  # not last element - reverse
        try:
            return handler(SymmetricCipher.decode(value, key))
        except Exception as e:
            print(e)
            continue
    raise ValueError("No key found")


def encode_cipher_key(
    value: bytes,
    handler: SerializerFunctionWrapHandler,
    info: SerializationInfo,
) -> str:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    if keys:
        return handler(SymmetricCipher.encode(value, keys[-2]))
    raise ValueError("No key found")


SecretCipherKey = Annotated[
    bytes, WrapValidator(decode_cipher_key), WrapSerializer(encode_cipher_key)
]


def decode_key(
    value: str, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
) -> bytes:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    for key in keys[::-1]:
        try:
            return handler(SymmetricCipher.decode(value, key))
        except Exception as e:
            print(e)
            continue
    raise ValueError("No key found")


def encode_key(
    value: Any, handler: SerializerFunctionWrapHandler, info: SerializationInfo
) -> bytes:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    if keys:
        SymmetricCipher.encode(handler(value), keys[-1])
    raise ValueError("No key found")


SecretKey = Annotated[
    bytes, WrapValidator(decode_key), WrapSerializer(encode_key)
]


def decode_rsa(
    value: str, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
) -> RSA.RsaKey:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    for key in keys[::-1]:
        try:
            return handler(RSA.importKey(SymmetricCipher.decode(value, key)))
        except Exception as e:
            print(e)
            continue
    raise ValueError("No key found")


def encode_rsa(
    value: RSA.RsaKey,
    handler: SerializerFunctionWrapHandler,
    info: SerializationInfo,
) -> bytes:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    if keys:
        return handler(
            SymmetricCipher.encode(
                handler(value.exportKey("DER", pkcs=8)), keys[-1]
            )
        )
    raise ValueError("No key found")


SecretRSA = Annotated[
    RSA.RsaKey, WrapValidator(decode_rsa), WrapSerializer(encode_rsa)
]
