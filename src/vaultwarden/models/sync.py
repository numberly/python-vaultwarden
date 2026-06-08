import time
from typing import Any, Self, cast
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

from vaultwarden.models.crypto import (
    SecretBytes,
    SecretOrganizationKey,
    SecretRSA,
)
from vaultwarden.models.enum import KdfType, VaultwardenUserStatus
from vaultwarden.models.permissive_model import PermissiveBaseModel
from vaultwarden.utils.crypto import SymmetricCipher


class ConnectToken(PermissiveBaseModel):
    Kdf: KdfType = KdfType.Pbkdf2
    KdfIterations: int = 0
    KdfMemory: int | None = None
    KdfParallelism: int | None = None
    Key: SecretBytes
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

    @field_validator("Key", mode="wrap")
    @classmethod
    def val_field_key(cls, v: str, handler: Any, info: ValidationInfo) -> str:
        assert info and info.context
        r = handler(v)

        cctx = cast("list[bytes]", info.context["cctx"])
        cctx.append(r)
        return r

    @model_validator(mode="wrap")
    @classmethod
    def val_set_key(
        cls,
        data: Any,
        handler: ModelWrapValidatorHandler[Self],
        info: ValidationInfo,
    ) -> Self:
        from vaultwarden.clients.bitwarden import BitwardenAPIClient
        from vaultwarden.models.bitwarden import Kdf
        from vaultwarden.utils.crypto import make_master_key

        assert info and info.context

        client: BitwardenAPIClient = cast(
            BitwardenAPIClient, info.context["client"]
        )
        cctx: list[bytes] = cast("list[bytes]", info.context["cctx"])

        master_key = make_master_key(
            password=client.password,
            salt=client.email,
            kdf=Kdf.model_validate(data),
        )
        cctx.append(master_key)
        v = handler(data)
        cctx.pop()  # Key
        cctx.pop()  # master_key
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
    Key: SecretBytes
    MasterPasswordHint: str | None = None
    Name: str | None
    Object: str | None
    Organizations: list[ProfileOrganization]
    Premium: bool
    PrivateKey: SecretRSA | None
    ProviderOrganizations: list
    Providers: list
    SecurityStamp: str
    TwoFactorEnabled: bool
    # original Bitwarden doesn't support disabling users
    status: VaultwardenUserStatus = Field(
        default=VaultwardenUserStatus.Enabled,
        validation_alias=AliasChoices("_status", "_Status"),
    )

    @model_validator(mode="wrap")
    @classmethod
    def val_set_key(
        cls,
        data: Any,
        handler: ModelWrapValidatorHandler[Self],
        info: ValidationInfo,
    ) -> Self:
        cctx: list[bytes]
        key: str
        if (key := data.get("key")) is not None:
            context = cast("dict", info.context)
            cctx = cast("list[bytes]", context.get("cctx"))
            cipher, ct = SymmetricCipher.parse(key[1:])
            v = cipher.decrypt(ct, cctx[-1])
            cctx.append(v)

        r = handler(data)
        if key:
            cctx.pop(0)

        return r


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
