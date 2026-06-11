import sys
import time
from typing import Any, cast
from uuid import UUID

from pydantic import (
    AliasChoices,
    Field,
    ModelWrapValidatorHandler,
    PrivateAttr,
    ValidationInfo,
    field_validator,
    model_validator,
)

from vaultwarden.models.bitwarden import Login, val_set_key
from vaultwarden.models.crypto import (
    CryptoContext,
    SecretKey,
    SecretOrganizationKey,
    SecretRSA,
)
from vaultwarden.models.enum import KdfType, VaultwardenUserStatus
from vaultwarden.models.permissive_model import PermissiveBaseModel

if sys.version_info < (3, 11):
    from typing_extensions import Self
else:
    from typing import Self


class ConnectToken(PermissiveBaseModel):
    Kdf: KdfType = KdfType.Pbkdf2
    KdfIterations: int = 0
    KdfMemory: int | None = None
    KdfParallelism: int | None = None
    Key: SecretKey
    PrivateKey: SecretRSA
    access_token: str
    refresh_token: str | None = None
    expires_in: int
    token_type: str
    scope: str
    unofficialServer: bool = False
    ResetMasterPassword: bool | None = None

    _master_key: bytes | None = PrivateAttr(default=None)

    @field_validator("expires_in")
    @classmethod
    def expires_in_to_time(cls, v):
        return time.time() + v

    def is_expired(self, now=None):
        if now is None:
            now = time.time()
        return (self.expires_in is not None) and (self.expires_in <= now)

    @model_validator(mode="wrap")
    @classmethod
    def val_set_key(
        cls,
        data: Any,
        handler: ModelWrapValidatorHandler[Self],
        info: ValidationInfo,
    ) -> Self:
        from vaultwarden.models.bitwarden import Kdf
        from vaultwarden.models.crypto import CryptoContext
        from vaultwarden.utils.crypto import make_master_key

        assert info and info.context
        ctx = cast(CryptoContext, info.context)

        master_key = make_master_key(
            password=ctx.client.password,
            salt=ctx.client.email,
            kdf=Kdf.model_validate(data),
        )
        ctx.push(master_key)
        v = val_set_key(cls, data, handler, info)
        ctx.pop()  # master_key
        v._master_key = master_key
        return v


class ProfileOrganization(PermissiveBaseModel):
    Id: UUID
    Name: str
    Key: SecretOrganizationKey | None = None
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
    Key: SecretKey
    MasterPasswordHint: str | None = None
    Name: str | None
    Object: str | None
    PrivateKey: SecretRSA | None
    Organizations: list[ProfileOrganization]
    Premium: bool
    ProviderOrganizations: list
    Providers: list
    SecurityStamp: str
    TwoFactorEnabled: bool
    # original Bitwarden doesn't support disabling users
    status: VaultwardenUserStatus = Field(
        default=VaultwardenUserStatus.Enabled,
        validation_alias=AliasChoices("_status", "_Status"),
    )

    @field_validator("Organizations", mode="wrap")
    @classmethod
    def val_field_Organizations(  # noqa: N802
        cls,
        v: str,
        handler: ModelWrapValidatorHandler[Self],
        info: ValidationInfo,
    ) -> Self:
        ctx: CryptoContext = cast(CryptoContext, info.context)
        ctx.push(info.data["PrivateKey"])
        r = handler(v)
        ctx.pop()
        return r

    @model_validator(mode="wrap")
    @classmethod
    def val_set_key(
        cls,
        data: Any,
        handler: ModelWrapValidatorHandler[Self],
        info: ValidationInfo,
    ) -> Self:
        return val_set_key(cls, data, handler, info)


class VaultwardenUser(UserProfile):
    UserEnabled: bool
    CreatedAt: str
    LastActive: str | None = None


class SyncData(PermissiveBaseModel):
    Profile: UserProfile
    Ciphers: list[Login]
    Collections: list[dict]
    Domains: dict | None
    Folders: list[dict]
    Policies: list[dict]
    Sends: list[dict]

    @model_validator(mode="wrap")
    @classmethod
    def val_set_key(
        cls,
        data: Any,
        handler: ModelWrapValidatorHandler[Self],
        info: ValidationInfo,
    ) -> Self:
        ctx: CryptoContext = cast(CryptoContext, info.context)

        assert (
            ctx.client._connect_token and ctx.client._connect_token._master_key
        )
        ctx.push(ctx.client._connect_token._master_key)
        r = handler(data)
        ctx.pop()
        return r
