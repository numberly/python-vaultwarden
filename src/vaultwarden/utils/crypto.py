#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Original source:
# https://github.com/corpusops/bitwardentools/blob/main/src/bitwardentools/crypto.py

import base64
import hashlib
import re
import secrets
import string
from base64 import b64decode, b64encode
from enum import IntEnum
from hashlib import pbkdf2_hmac, sha256
from hmac import new as hmac_new
from secrets import token_bytes
import typing

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from hkdf import hkdf_expand
from typing_extensions import override

if typing.TYPE_CHECKING:
    import vaultwarden.models.bitwarden

class CIPHERS(IntEnum):
    null = 0
    sym = 2
    asym = 4


CACHE = {}  # type: ignore
ENCRYPTED_STRING_RE = re.compile("^[0-9][.].*=.*", flags=re.I | re.M)
SYM_ENCRYPTED_STRING_RE = re.compile(
    "^2[.][^=]+=+[|][^=]+=+[|][^=]+=+", flags=re.I | re.M
)

class _Cipher:
    TYPE: int
    ENCODING: str
    @classmethod
    def encode(cls, plainbytes:bytes, key:bytes) -> str:
        raise NotImplementedError()

    @classmethod
    def decode(cls, data, key) -> bytes:
        raise NotImplementedError()

    def _decrypt(self, data:bytes, key: bytes) -> bytes:
        raise NotImplementedError()

class AsymmetricCipher(_Cipher):
    TYPE = CIPHERS.asym
    ENCODING = "{typ}.{b64_ct}"
    @classmethod
    def _parse(cls, ct:str) -> tuple[typing.Self, bytes]:
        return cls(), b64decode(ct)

    def _decrypt(self, ct:bytes, key: RSA.RsaKey) -> bytes:
        assert isinstance(ct, bytes)
        assert isinstance(key, RSA.RsaKey)
        return PKCS1_OAEP.new(key).decrypt(ct)

    @classmethod
    def encode(cls, plainbytes: bytes, key: RSA.RsaKey):
        assert isinstance(plainbytes, bytes)
        assert isinstance(key, RSA.RsaKey)
        cipher = PKCS1_OAEP.new(key).encrypt(plainbytes)
        b64_ct = b64encode(cipher).decode()
        return cls.ENCODING.format(cipher=cipher, b64_ct=b64_ct)

    @classmethod
    def decode(cls, data: str, key: RSA.RsaKey) -> bytes:
        assert int(data[0]) == AsymmetricCipher.TYPE
        cipher, ct = cls._parse(data[1:])
        return cipher._decrypt(ct, key)

class SymmetricCipher(_Cipher):
    TYPE = CIPHERS.sym
    ENCODING = "{typ}.{b64_iv}|{b64_ct}|{b64_digest}"
    def __init__(self, iv:bytes, mac:bytes):
        self._iv = iv
        self._mac = mac

    @classmethod
    def _parse(cls, ct: str) -> tuple[typing.Self, bytes]:
        iv, ct, mac = ct.split("|", 3)
        return cls(b64decode(iv), b64decode(mac)[0:32]), b64decode(ct)

    def _decrypt(self, ct: bytes, key: bytes) -> bytes:
        assert isinstance(ct, bytes)
        assert isinstance(key, bytes)
        enc, mac = SymmetricCipher._get_enc_mac(key)
        hdmac = hmac_new(mac, self._iv + ct, sha256).digest()
        if hdmac != self._mac:
            raise DecryptError(
                f"Symmetric hmac verification failed {bytes(hdmac).hex()} / {bytes(self._mac).hex()}. Check your password."
            )
        c = AES.new(enc, AES.MODE_CBC, self._iv)
        plaintext = c.decrypt(ct)
        pad_len = plaintext[-1]
        padding = bytes([pad_len] * pad_len)
        if plaintext[-pad_len:] == padding:
            plaintext = plaintext[:-pad_len]
        return plaintext


    @classmethod
    def encode(cls, plainbytes: bytes, key: bytes) -> str:
        assert isinstance(plainbytes, bytes)
        assert isinstance(key, bytes)
        # inspired from bitwarden/jslib:src/services/crypto.service.ts
        typ = int(CIPHERS.sym)
        (iv, ct, mac) = aes_encrypt(plainbytes, key)
        # jslib: encrypt()
        b64_iv = b64encode(iv).decode()
        b64_ct = b64encode(ct).decode()
        b64_digest = ""
        if mac:
            b64_digest = b64encode(mac).decode()
        return cls.ENCODING.format(typ=CIPHERS.sym, b64_iv=b64_iv, b64_ct=b64_ct, b64_digest=b64_digest)

    @classmethod
    def decode(cls, data: str, key: bytes) -> bytes:
        assert int(data[0]) == SymmetricCipher.TYPE
        cipher, ct = cls._parse(data[1:])
        return cipher._decrypt(ct, key)


    @staticmethod
    def _get_enc_mac(key:bytes) -> tuple[bytes, bytes]:
        assert isinstance(key, bytes)
        #
        match len(key):
            case 32:
                """symmetric master_key of the user"""
                enc = hkdf_expand(key, b"enc", 32, sha256)
                mac = hkdf_expand(key, b"mac", 32, sha256)
            case 64:
                """symmetric key of an organization"""
                enc = key[:32]
                mac = key[32:]
            case _:
                raise ValueError(f"Invalid key type {key!r}")
        return enc, mac


class BinarySymmetricCipher:
    ENCODING = b"%(typ)c%(iv)16b%(mac)32b%(ct)b"

    def __init__(self, iv:bytes, mac:bytes):
        self._iv = iv
        self._mac = mac

    @classmethod
    def _parse(cls, cipher_bytes: bytes) -> tuple[typing.Self, bytes]:
        iv = cipher_bytes[1:17]
        mac = cipher_bytes[17:49]
        ct = cipher_bytes[49:]
        return cls(iv, mac), ct

    def _decrypt(self, ct: bytes, key: bytes) -> bytes:
        assert isinstance(ct, bytes)
        assert isinstance(key, bytes)
        enc, mac = SymmetricCipher._get_enc_mac(key)
        hdmac = hmac_new(mac, self._iv + ct, sha256).digest()
        if hdmac != self._mac:
            raise DecryptError(
                f"Symmetric hmac verification failed {bytes(hdmac).hex()} / {bytes(self._mac).hex()}. Check your password."
            )
        c = AES.new(enc, AES.MODE_CBC, self._iv)
        plaintext = c.decrypt(ct)
        pad_len = plaintext[-1]
        padding = bytes([pad_len] * pad_len)
        if plaintext[-pad_len:] == padding:
            plaintext = plaintext[:-pad_len]
        return plaintext


    def decode(cls, data: bytes, key: bytes) -> bytes:
        assert isinstance(data, bytes)
        assert isinstance(key, bytes)
        assert int(data[0]) == SymmetricCipher.TYPE
        cipher, ct = cls._parse(data[1:])
        return cipher._decrypt(ct, key)


    @classmethod
    def encode(cls, plainbytes: bytes, key: bytes) -> bytes:
        assert isinstance(plainbytes, bytes)
        assert isinstance(key, bytes)
        # inspired from bitwarden/jslib:src/services/crypto.service.ts
        typ = int(CIPHERS.sym)
        (iv, ct, mac) = aes_encrypt(plainbytes, key)
        # jslib: encryptToBytes()
        ret = chr(typ).encode()
        ret += iv
        if mac:
            ret += mac
        ret += ct

        assert cls.ENCODING % {"typ": typ, "iv": iv, "mac": mac, "ct": ct} == ret
        return ret


class NullCipher(_Cipher):
    TYPE = CIPHERS.null
    def __init__(self, iv, ct):
        self._iv = iv
        self._ct = ct

    @classmethod
    def parse(cls, ct):
        iv, ct, mac = ct.split("|", 2)
        iv = b64decode(iv)
        ct = b64decode(ct)
        return cls(iv), ct


class UnimplementedError(Exception):
    """."""


class DecodeEncKeyError(ValueError):
    """."""


class WrongFormatError(DecodeEncKeyError):
    """."""


class WrongTypeDecryptError(DecodeEncKeyError):
    """."""


class MissingPartsDecryptError(DecodeEncKeyError):
    """."""


class B64DecryptError(DecodeEncKeyError):
    """."""


class DecryptError(ValueError):
    """."""


def make_master_key(password: str, salt: str, kdf: "vaultwarden.models.bitwarden.Kdf"):
    import vaultwarden.models.bitwarden

    assert isinstance(salt, str)
    assert isinstance(password, str)

    password_: bytes = password.encode("utf-8")
    salt_: bytes = salt.lower().encode("utf-8")

    match kdf.Kdf:
        case vaultwarden.models.bitwarden.KdfType.Pbkdf2:
            assert kdf.KdfIterations is not None
            return pbkdf2_hmac("sha256", password_, salt_, kdf.KdfIterations)
        case vaultwarden.models.bitwarden.KdfType.Argon2id:
            # c.f.
            # https://github.com/vaultwarden/vw_web_builds/blob/355bddc6c9d5c110e55fe74c5fcfa86ddd85572c/libs/common/src/platform/services/key-generation.service.ts#L55-L75
            import argon2
            assert kdf.KdfIterations is not None
            assert kdf.KdfMemory is not None
            assert kdf.KdfParallelism is not None
            hsalt = hashlib.new("sha256", salt_).digest()
            v = argon2.low_level.hash_secret_raw(
                password_,
                hsalt,
                time_cost=kdf.KdfIterations,
                memory_cost=kdf.KdfMemory * 1024,
                parallelism=kdf.KdfParallelism,
                hash_len=32,
                type=argon2.Type.ID,
            )
            return v

def hash_password(password: str, salt: str, kdf: "vaultwarden.models.bitwarden.Kdf"): # FIXME UNUSED
    """base64-encode a wrapped, stretched password+salt(email) for signup/login"""
    assert isinstance(password, str)
    assert isinstance(salt, str)
    master_key = make_master_key(password, salt, kdf)
    hashpw = hashlib.pbkdf2_hmac("sha256", master_key, password.encode(), 1)
    return base64.b64encode(hashpw), master_key


def aes_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    assert isinstance(plaintext, bytes)
    assert isinstance(key, bytes)

    enc, mac = SymmetricCipher._get_enc_mac(key)

    pad_len = 16 - len(plaintext) % 16
    padding = bytes([pad_len] * pad_len)
    content = plaintext + padding
    iv = token_bytes(16)
    c = AES.new(enc, AES.MODE_CBC, iv)
    ct = c.encrypt(content)
    cmac = hmac_new(mac, iv + ct, sha256)
    return iv, ct, cmac.digest()


def strech_key(key: bytes) -> bytes:
    stretched_key = key
    if len(stretched_key) < 64:
        stretched_key = hkdf_expand(key, b"enc", 32, sha256) + hkdf_expand(
            key, b"mac", 32, sha256
        )
    return stretched_key

def make_sym_key(master_key: bytes) -> tuple[str, bytes]: # FIXME UNUSED
    stretched_key = strech_key(master_key)
    plaintext = token_bytes(64)
    return SymmetricCipher.encode(plaintext, stretched_key), plaintext


def make_asym_key(key:bytes, stretch=True) -> tuple[str, bytes, bytes]:  # FIXME UNUSED
    if stretch:
        key = strech_key(key)
    asym_key = RSA.generate(2048)
    public_key = asym_key.publickey().exportKey("DER")
    private_key = asym_key.exportKey("DER", pkcs=8)
    return SymmetricCipher.encode(private_key, key), public_key, private_key


def gen_password(length=32, alphabet=None) -> str:  # FIXME UNUSED
    alphabet = alphabet or string.ascii_letters + string.digits
    while True:
        password = "".join(secrets.choice(alphabet) for i in range(length))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and sum(c.isdigit() for c in password) >= 3
        ):
            break
    return password


# vim:set et sts=4 ts=4 tw=120:
