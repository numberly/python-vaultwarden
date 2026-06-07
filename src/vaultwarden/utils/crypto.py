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
    def encrypt(cls, plainbytes:bytes, key:bytes) -> str:
        raise NotImplementedError()

    def decrypt(self, data:bytes, key: bytes) -> bytes:
        raise NotImplementedError()

class AsymmetricCipher(_Cipher):
    TYPE = CIPHERS.asym
    ENCODING = "{typ}.{b64_ct}"
    @classmethod
    def parse(cls, ct:str) -> tuple[typing.Self, bytes]:
        return cls(), b64decode(ct)

    @classmethod
    def encrypt(cls, plainbytes: bytes, key: bytes):
        assert isinstance(plainbytes, bytes)
        assert isinstance(key, bytes)
        cipher = PKCS1_OAEP.new(load_rsa_key(key)).encrypt(plainbytes)
        b64_ct = b64encode(cipher).decode()
        return cls.ENCODING.format(cipher=cipher, b64_ct=b64_ct)

    def decrypt(self, ct:bytes, key: bytes):
        assert isinstance(ct, bytes)
        assert isinstance(key, bytes)
        return PKCS1_OAEP.new(load_rsa_key(key)).decrypt(ct)


class SymmetricCipher(_Cipher):
    TYPE = CIPHERS.sym
    ENCODING = "{typ}.{b64_iv}|{b64_ct}|{b64_digest}"
    def __init__(self, iv:bytes, mac:bytes):
        self._iv = iv
        self._mac = mac

    @classmethod
    def parse(cls, ct: str) -> tuple[typing.Self, bytes]:
        iv, ct, mac = ct.split("|", 3)
        return cls(b64decode(iv), b64decode(mac)[0:32]), b64decode(ct)

    @classmethod
    def encrypt(cls, plainbytes: bytes, key: bytes) -> str:
        assert isinstance(plainbytes, bytes)
        assert isinstance(key, bytes)
        return cls._encrypt_sym(plainbytes, key)


    def decrypt(self, ct: bytes, key: bytes) -> bytes:
        assert isinstance(ct, bytes)
        assert isinstance(key, bytes)
        return SymmetricCipher._decrypt_sym(dct=ct, key=key, div=self._iv, dmac=self._mac)


    @staticmethod
    def _get_enc_mac(key:bytes) -> tuple[bytes, bytes]:
        assert isinstance(key, bytes)
        # symmetric master_key of the user
        if len(key) == 32:
            enc = hkdf_expand(key, b"enc", 32, sha256)
            mac = hkdf_expand(key, b"mac", 32, sha256)
        # symmetric key of an organization
        elif len(key) == 64:
            enc = key[:32]
            mac = key[32:]
        return enc, mac

    @staticmethod
    def _decrypt_sym(dct:bytes, key:bytes, div:bytes, dmac:bytes) -> bytes:
        assert isinstance(dct, bytes)
        assert isinstance(key, bytes)
        assert isinstance(div, bytes)
        assert isinstance(dmac, bytes)

        enc, mac = SymmetricCipher._get_enc_mac(key)
        hdmac = hmac_new(mac, div + dct, sha256).digest()
        if hdmac != dmac:
            raise DecryptError(
                f"Symmetric hmac verification failed {bytes(hdmac).hex()} / {bytes(dmac).hex()}. Check your password."
            )
        c = AES.new(enc, AES.MODE_CBC, div)
        plaintext = c.decrypt(dct)
        pad_len = plaintext[-1]
        padding = bytes([pad_len] * pad_len)
        if plaintext[-pad_len:] == padding:
            plaintext = plaintext[:-pad_len]
        return plaintext

    @classmethod
    def _encrypt_sym(cls, plaintext: bytes, key: bytes) -> str:
        assert isinstance(plaintext, bytes)
        assert isinstance(key, bytes)
        # inspired from bitwarden/jslib:src/services/crypto.service.ts
        typ = int(CIPHERS.sym)
        (iv, ct, mac) = aes_encrypt(plaintext, key)
        # jslib: encrypt()
        b64_iv = b64encode(iv).decode()
        b64_ct = b64encode(ct).decode()
        b64_digest = ""
        if mac:
            b64_digest = b64encode(mac).decode()
        return cls.ENCODING.format(typ=CIPHERS.sym, b64_iv=b64_iv, b64_ct=b64_ct,b64_digest=b64_digest)


class BinarySymmetricCipher:
    ENCODING = b"%(typ)c%(iv)16b%(mac)32b%(ct)b"

    def __init__(self, iv:bytes, mac:bytes):
        self._iv = iv
        self._mac = mac

    @classmethod
    def parse(cls, cipher_bytes: bytes) -> tuple[typing.Self, bytes]:
        iv = cipher_bytes[1:17]
        mac = cipher_bytes[17:49]
        ct = cipher_bytes[49:]
        return cls(iv, mac), ct


    def decrypt(self, ct: bytes, key: bytes) -> bytes:
        assert isinstance(ct, bytes)
        assert isinstance(key, bytes)
        return SymmetricCipher._decrypt_sym(dct=ct, key=key, div=self._iv, dmac=self._mac)


    @classmethod
    def encrypt(cls, plainbytes: bytes, key: bytes) -> bytes:
        assert isinstance(plainbytes, bytes)
        assert isinstance(key, bytes)
        return cls._encrypt_sym_bytes(plainbytes, key)

    @classmethod
    def _encrypt_sym_bytes(cls, plainbytes: bytes, key: bytes) -> bytes:
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


def decode_cipher_string(cipher_string: str) -> tuple[_Cipher, bytes]:
    """decode a cipher tring into it's parts"""
    assert isinstance(cipher_string, str)
    if not ENCRYPTED_STRING_RE.match(cipher_string):
        raise WrongFormatError(f"{cipher_string}")
    try:
        typ = CIPHERS(int(cipher_string[0:1]))
        assert typ < 9
    except (AssertionError, ValueError):
        raise WrongTypeDecryptError(f"{typ} is not valid")
    data = cipher_string[2:]
    match typ:
        case CIPHERS.asym:
            return AsymmetricCipher.parse(data)
        case CIPHERS.sym:
            return SymmetricCipher.parse(data)
        case CIPHERS.null:
            return NullCipher.parse(data)


def is_encrypted(cipher_string: str) -> bool: # FIXME unused
    try:
        decode_cipher_string(cipher_string)
    except DecodeEncKeyError:
        return False
    else:
        return True


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


def load_rsa_key(key: bytes) -> RSA.RsaKey:
    rsakeys = CACHE.setdefault("rsa", {})
    if not isinstance(key, RSA.RsaKey):
        try:
            key = rsakeys[key]
        except KeyError:
            rsakeys[key] = RSA.importKey(key)
            key = rsakeys[key]
    return key


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


def encrypt_sym_to_bytes(plaintext: str, key: bytes): # FIXME migrated
    assert isinstance(plaintext, str)
    return BinarySymmetricCipher.encrypt(plaintext.encode("utf-8"), key)


def encrypt(typ:CIPHERS|int, plaintext: str, key: bytes):
    assert isinstance(typ, (CIPHERS, int)), typ
    assert isinstance(plaintext, str)
    assert isinstance(key, bytes)

    plainbytes = plaintext.encode("utf-8")
    match typ:
        case AsymmetricCipher.TYPE:
            return AsymmetricCipher.encrypt(plainbytes, key)
        case SymmetricCipher.TYPE:
            return SymmetricCipher.encrypt(plainbytes, key)
        case _:
            raise UnimplementedError(f"can not encrypt type:{typ}")



def decrypt_bytes(cipher_bytes: bytes, key: bytes): # FIXME UNUSED
    assert isinstance(cipher_bytes, bytes)
    assert isinstance(key, bytes)
    typ = cipher_bytes[0]
    match typ:
        case SymmetricCipher.TYPE:
            cipher, ct = BinarySymmetricCipher.parse(cipher_bytes)
            return cipher.decrypt(ct, key)
        case _:
            raise UnimplementedError(f"{typ} encType decryption is not implemented")

def decrypt(cipher_string: str, key:bytes) -> bytes:
    assert isinstance(cipher_string, str)
    cipher, ct = decode_cipher_string(cipher_string)
    return cipher.decrypt(ct, key)

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
    return SymmetricCipher.encrypt(plaintext, stretched_key), plaintext


def make_asym_key(key:bytes, stretch=True) -> tuple[str, bytes, bytes]:  # FIXME UNUSED
    if stretch:
        key = strech_key(key)
    asym_key = RSA.generate(2048)
    public_key = asym_key.publickey().exportKey("DER")
    private_key = asym_key.exportKey("DER", pkcs=8)
    return SymmetricCipher.encrypt(private_key, key), public_key, private_key


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
