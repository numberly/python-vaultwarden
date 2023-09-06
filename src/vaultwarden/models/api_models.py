import time
from typing import Literal, TypedDict

from bitwardentools.crypto import decrypt


class ApiToken:
    token: dict
    expires: float

    def __init__(self, token, master_key, expires_in: int):
        self.token = token
        self.expires = time.time() + expires_in
        self.token["user_key"] = decrypt(token["Key"], master_key)
        self.token["orgs_key"] = decrypt(
            token["PrivateKey"], self.token["user_key"]
        )

    def is_expired(self, now=None):
        if now is None:
            now = time.time()
        if (self.expires is not None) and (self.expires <= now):
            return True
        return False

    def refresh(
        self,
        token,
    ):
        self.token["access_token"] = token["access_token"]
        self.token["expires_in"] = token["expires_in"]
        self.expires = time.time() + token["expires_in"]

    def bearer(self):
        return self.token.get("access_token", None)

    def get(self, key, default=None):
        return self.token.get(key, default)


class VaultWardenOrg(TypedDict):
    Id: str
    Name: str
    Object: str


class VaultWardenUser(TypedDict):
    CreatedAt: str
    SecurityStamp: str
    _Status: int
    Key: str
    Email: str
    EmailVerified: bool
    ForcePasswordReset: bool
    Id: str
    Name: str
    Object: Literal["profile"]
    Organizations: list[VaultWardenOrg]
    UserEnabled: bool
    TwoFactorEnabled: bool
