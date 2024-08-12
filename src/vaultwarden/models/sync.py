import time
from uuid import UUID

from pydantic import AliasChoices, Field, field_validator

from vaultwarden.models.enum import VaultwardenUserStatus
from vaultwarden.models.permissive_model import PermissiveBaseModel
from vaultwarden.utils.crypto import decrypt


class ConnectToken(PermissiveBaseModel):
    Kdf: int = 0
    KdfIterations: int = 0
    KdfMemory: int | None = None
    KdfParallelism: int | None = None
    Key: str
    PrivateKey: str
    access_token: str
    refresh_token: str | None = None
    expires_in: int
    token_type: str
    scope: str
    unofficialServer: bool = False
    ResetMasterPassword: bool | None = None
    master_key: bytes | None = None

    @field_validator("expires_in")
    @classmethod
    def expires_in_to_time(cls, v):
        return time.time() + v

    def is_expired(self, now=None):
        if now is None:
            now = time.time()
        return (self.expires_in is not None) and (self.expires_in <= now)

    @property
    def user_key(self):
        return decrypt(self.Key, self.master_key)

    @property
    def orgs_key(self):
        return decrypt(self.PrivateKey, self.user_key)


class ProfileOrganization(PermissiveBaseModel):
    Id: UUID
    Name: str
    Key: str | None = None
    ProviderId: str | None = None
    ProviderName: str | None = None
    ResetPasswordEnrolled: bool
    Seats: int | None = None
    SelfHost: bool
    SsoBound: bool
    Status: int
    Type: int
    Use2fa: bool
    UseApi: bool
    UseDirectory: bool
    UseEvents: bool
    UseGroups: bool
    UsePolicies: bool
    UseResetPassword: bool
    UseSso: bool
    UseTotp: bool


class UserProfile(PermissiveBaseModel):
    AvatarColor: str | None
    Culture: str
    Email: str
    EmailVerified: bool
    ForcePasswordReset: bool
    Id: UUID
    Key: str
    MasterPasswordHint: str | None
    Name: str
    Object: str | None
    Organizations: list[ProfileOrganization]
    Premium: bool
    PrivateKey: str | None
    ProviderOrganizations: list
    Providers: list
    SecurityStamp: str
    TwoFactorEnabled: bool
    status: VaultwardenUserStatus = Field(
        validation_alias=AliasChoices("_status", "_Status")
    )


class VaultwardenUser(UserProfile):
    UserEnabled: bool
    CreatedAt: str
    LastActive: str | None = None


# TODO: add definition of attribute's types
class SyncData(PermissiveBaseModel):
    Ciphers: list[dict]
    Collections: list[dict]
    Domains: dict | None
    Folders: list[dict]
    Policies: list[dict]
    Profile: UserProfile
    Sends: list[dict]
