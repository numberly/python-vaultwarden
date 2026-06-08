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
        if len(key) <= 64:
            continue
        try:
            assert int(value[0]) == AsymmetricCipher.TYPE
            cipher, ct = AsymmetricCipher.parse(value[1:])
            return handler(cipher.decrypt(ct, key))
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
        return handler(AsymmetricCipher.encrypt(value, keys[-2]))
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
            cipher, ct = SymmetricCipher.parse(handler(value)[1:])
            return handler(cipher.decrypt(ct, key))
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
        return handler(SymmetricCipher.encrypt(value.encode(), keys[-1]))
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
            assert int(value[0]) == SymmetricCipher.TYPE
            cipher, ct = SymmetricCipher.parse(value[1:])
            return handler(cipher.decrypt(ct, key))
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
        return handler(SymmetricCipher.encrypt(value, keys[-2]))
    raise ValueError("No key found")


SecretCipherKey = Annotated[
    bytes, WrapValidator(decode_cipher_key), WrapSerializer(encode_cipher_key)
]


def decode_bytes(
    value: str, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
) -> bytes:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    for key in keys[::-1]:
        try:
            cipher, ct = SymmetricCipher.parse(value[1:])
            return handler(cipher.decrypt(ct, key))
        except Exception as e:
            print(e)
            continue
    raise ValueError("No key found")


def encode_bytes(
    value: Any, handler: SerializerFunctionWrapHandler, info: SerializationInfo
) -> bytes:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    if keys:
        SymmetricCipher.encrypt(handler(value), keys[-1])
    raise ValueError("No key found")


SecretBytes = Annotated[
    bytes, WrapValidator(decode_bytes), WrapSerializer(encode_bytes)
]


def decode_rsa(
    value: str, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
) -> RSA.RsaKey:
    context: dict = cast("dict", info.context)
    keys: list[bytes] = cast("list[bytes]", context.get("cctx"))
    for key in keys[::-1]:
        try:
            cipher, ct = SymmetricCipher.parse(value[1:])
            return handler(RSA.importKey(cipher.decrypt(ct, key)))
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
        SymmetricCipher.encrypt(
            handler(value.exportKey("DER", pkcs=8)), keys[-1]
        )
    raise ValueError("No key found")


SecretRSA = Annotated[
    RSA.RsaKey, WrapValidator(decode_rsa), WrapSerializer(encode_rsa)
]
