import base64
import datetime
from enum import IntEnum
from functools import cached_property
import io
from pathlib import Path
from secrets import token_bytes
import sys
import typing
from typing import (
    TYPE_CHECKING,
    Annotated,
    Any,
    Generic,
    Literal,
    TypeVar,
    Union,
    cast,
)
from uuid import UUID

from Crypto.PublicKey import RSA
from pydantic import (
    AliasChoices,
    ConfigDict,
    Field,
    ModelWrapValidatorHandler,
    PrivateAttr,
    TypeAdapter,
    computed_field,
    field_validator,
    model_serializer,
    model_validator,
)
from pydantic_core.core_schema import (
    SerializationInfo,
    SerializerFunctionWrapHandler,
    ValidationInfo,
)

from vaultwarden.models.crypto import (
    CryptoContext,
    RSAPublicKey,
    SecretBytes,
    SecretKey,
    SecretOrganizationKey,
    SecretString,
)
from vaultwarden.models.enum import CipherType, KdfType, OrganizationUserType
from vaultwarden.models.exception_models import BitwardenError
from vaultwarden.models.permissive_model import PermissiveBaseModel
from vaultwarden.utils.crypto import (
    AsymmetricCipher,
    BinarySymmetricCipher,
    SymmetricCipher,
    make_master_key,
    masterPasswordHash,
    stretch_key,
)

if TYPE_CHECKING:
    from vaultwarden.clients.bitwarden import BitwardenAPIClient
    from vaultwarden.models.sync import ProfileOrganization

if sys.version_info < (3, 11):
    from typing_extensions import Self
else:
    from typing import Self


# Pydantic models for Bitwarden data structures

T = TypeVar("T", bound="BitwardenBaseModel")


def val_set_key(
    cls,
    data: Any,
    handler: ModelWrapValidatorHandler[Any],
    info: ValidationInfo,
) -> Any:
    key: str
    ctx: CryptoContext = cast(CryptoContext, info.context)
    if (key := (data.get("key") or data.get("Key"))) is not None:
        match int(key[0]):
            case SymmetricCipher.TYPE:
                assert isinstance(ctx.stack[-1], bytes)
                v = SymmetricCipher.decode(key, ctx.stack[-1])
            case AsymmetricCipher.TYPE:
                assert isinstance(ctx.stack[-1], RSA.RsaKey)
                v = AsymmetricCipher.decode(key, ctx.stack[-1])
        ctx.push(v)

    r = handler(data)

    if key is not None:
        ctx.pop()

    return r


def ser_set_key(
    slf: Any, handler: SerializerFunctionWrapHandler, info: SerializationInfo
) -> Any:
    key: bytes | None
    if (key := slf.Key) is not None:
        ctx: CryptoContext = cast(CryptoContext, info.context)
        ctx.push(key)

    v = handler(slf)

    if key is not None:
        ctx.pop()

    return v


class ResplistBitwarden(PermissiveBaseModel, Generic[T]):
    Data: list[T]


class BitwardenBaseModel(PermissiveBaseModel):
    _bitwarden_client: Any = PrivateAttr(default=None)

    @model_validator(mode="wrap")
    @classmethod
    def val_set_client(
        cls,
        data: Any,
        handler: ModelWrapValidatorHandler[Self],
        info: ValidationInfo,
    ) -> Self:
        ctx: CryptoContext = cast(CryptoContext, info.context)
        v = handler(data)
        v._bitwarden_client = ctx.client
        return v

    @property
    def api_client(self) -> "BitwardenAPIClient":
        assert self._bitwarden_client is not None
        return self._bitwarden_client


class UriMatchDetection(IntEnum):
    BASEDOMAIN = 0
    HOST = 1
    STARTSWITH = 2
    EXACT = 3
    RE = 4
    NEVER = 5


class UriMatch(BitwardenBaseModel):
    model_config = ConfigDict(extra="forbid")

    match: UriMatchDetection | None = None
    uri: SecretString | None = None
    uriChecksum: SecretString | None = None
    response: str | None = None

    def uri_match(self, name: str) -> bool:
        import re
        import urllib.parse

        if self.uri is None:
            return False
        m = self.match if self.match is not None else UriMatchDetection.HOST
        match m:
            case UriMatchDetection.BASEDOMAIN:
                url = urllib.parse.urlparse(name)
                if url.hostname is None:
                    return False
                basename = ".".join(url.hostname.split(".")[1:])
                hostname = urllib.parse.urlparse(self.uri).hostname
                return hostname == basename
            case UriMatchDetection.HOST:
                url = urllib.parse.urlparse(self.uri)
                hostname = urllib.parse.urlparse(name).hostname
                return hostname == url.hostname
            case UriMatchDetection.STARTSWITH:
                return name.startswith(self.uri)
            case UriMatchDetection.EXACT:
                return name == self.uri
            case UriMatchDetection.RE:
                return re.match(self.uri, name) is not None
            case UriMatchDetection.NEVER:
                return False


class XField(BitwardenBaseModel):
    model_config = ConfigDict(extra="forbid")

    name: SecretString | None = None
    response: SecretString | None = None
    type: int
    value: SecretString | None = None
    linkedId: str | None = None


class PasswordChange(BitwardenBaseModel):
    model_config = ConfigDict(extra="forbid")

    lastUsedDate: datetime.datetime
    password: SecretString


class Fido2Credential(BitwardenBaseModel):
    model_config = ConfigDict(extra="forbid")

    counter: SecretString | None = None
    creationDate: datetime.datetime | None = None
    credentialId: SecretString | None = None
    discoverable: SecretString | None = None
    keyAlgorithm: SecretString | None = None
    keyCurve: SecretString | None = None
    keyType: SecretString | None = None
    keyValue: SecretString | None = None
    response: str | None = None
    rpId: SecretString | None = None
    rpName: SecretString | None = None
    userDisplayName: SecretString | None = None
    userHandle: SecretString | None = None
    userName: SecretString | None = None


class AttachmentRequest(BitwardenBaseModel):
    model_config = ConfigDict(extra="forbid")

    Key: SecretBytes
    fileName: SecretString
    fileSize: int
    adminRequest: bool | None = None


class Attachment(BitwardenBaseModel):
    model_config = ConfigDict(extra="forbid")

    Key: SecretBytes
    fileName: SecretString | None = None
    id: str
    Object: str
    size: int
    sizeName: str
    url: str

    def download(self):
        v = self._bitwarden_client._http_client.get(self.url)
        return BinarySymmetricCipher.decode(v.content, self.key)


class _CipherBase(BitwardenBaseModel):
    model_config = ConfigDict(extra="forbid")

    Id: UUID | None = None
    OrganizationId: UUID | None = Field(None, validate_default=True)
    Type: CipherType
    Name: SecretString
    CollectionIds: list[UUID]
    Key: SecretKey | None = None

    OrganizationUseTotp: bool | None = None
    CreationDate: datetime.datetime | None = None
    DeletedDate: datetime.datetime | None = None
    Fields: list[XField] | None = None

    Notes: SecretString | None = None
    Reprompt: int | None = None
    ArchivedDate: str | None = None
    RevisionDate: str | None = None
    sshKey: str | None = None
    Object: str | None = None
    Attachments: list[Attachment] | None = None

    Edit: bool | None = None
    Favorite: bool | None = None
    FolderId: UUID | None = None
    Permissions: Any | None = None
    PasswordHistory: list[PasswordChange] | None = None
    ViewPassword: bool | None = None

    Login: None = None
    SecureNote: None = None
    Card: None = None
    Identity: None = None

    Data: Any | None = None

    @model_validator(mode="wrap")
    @classmethod
    def val_set_key(
        cls,
        data: Any,
        handler: ModelWrapValidatorHandler[Self],
        info: ValidationInfo,
    ) -> Self:
        assert isinstance(info.context, CryptoContext)

        ctx: CryptoContext = cast(CryptoContext, info.context)

        assert ctx.client._sync and ctx.client._sync.Profile

        if (
            o := data.get("organizationId") or data.get("OrganizationId")
        ) is not None:
            oid = UUID(o)
            org: typing.Optional["ProfileOrganization"] = None
            for org in ctx.client._sync.Profile.Organizations:
                if oid == org.Id:
                    assert org.Key
                    ctx.push(org.Key)
                    break
            else:
                raise ValueError(f"No organization found {oid}")
        else:
            assert ctx.client._connect_token
            ctx.push(ctx.client._connect_token.Key)
        r = val_set_key(cls, data, handler, info)

        ctx.pop()

        return r

    @model_serializer(mode="wrap")
    def ser_set_key(
        self, handler: SerializerFunctionWrapHandler, info: SerializationInfo
    ) -> Any:
        return ser_set_key(self, handler, info)

    @field_validator("OrganizationId")
    @classmethod
    def set_id(cls, v, info: ValidationInfo):
        if v is None and info.context is not None:
            ctx: CryptoContext = cast(CryptoContext, info.context)
            return ctx.parent_id
        return v

    def add_collections(self, collections: list[UUID]):
        _current_collections = self.CollectionIds
        for collection in collections:
            if collection in _current_collections:
                continue
            self.CollectionIds.append(collection)
        dump = [str(coll_id) for coll_id in self.CollectionIds]
        return self.api_client.api_request(
            "POST",
            f"api/ciphers/{self.Id}/collections",
            json={"collectionIds": dump},
        )

    def remove_collections(self, collections: list[UUID]):
        self.CollectionIds = [
            coll for coll in self.CollectionIds if coll not in collections
        ]
        dump = [str(coll_id) for coll_id in self.CollectionIds]
        return self.api_client.api_request(
            "POST",
            f"api/ciphers/{self.Id}/collections",
            json={"collectionIds": dump},
        )

    def collections(self):
        org: Organization | None = (
            get_organization(self._bitwarden_client, self.OrganizationId)
            if self.OrganizationId
            else None
        )
        if org is None:
            return []
        cd: dict[UUID, OrganizationCollection] = {
            o.Id: o for o in org.collections()
        }
        colls: list[OrganizationCollection] = [
            cd[i] for i in self.CollectionIds
        ]
        return colls

    def delete(self):
        return self.api_client.api_request("DELETE", f"api/ciphers/{self.Id}")

    def update_collection(self, collections: list[UUID]):
        dump = [str(coll_id) for coll_id in collections]
        self.CollectionIds = collections
        return self.api_client.api_request(
            "POST",
            f"api/ciphers/{self.Id}/collections",
            json={"collectionIds": dump},
        )

    def attach(self, path: Path):
        with path.open("rb") as f:
            self._attach(path.name, f)

    def _attach(self, name: str, file: io.IOBase):
        "/api/ciphers/fc246fe5-9177-455b-b318-c00fab407dc8/attachment/v2"
        key = token_bytes(64)
        ed = BinarySymmetricCipher.encode(file.read(), key)
        ar = AttachmentRequest.model_construct(
            Key=key, fileName=name, fileSize=len(ed), adminRequest=True
        )
        if self.OrganizationId:
            stack = [
                get_organization(
                    self._bitwarden_client, self.OrganizationId
                ).key()
            ]
        else:
            stack = [self._bitwarden_client._connect_token._masterKey]
        ard = ar.model_dump(
            mode="json",
            context=CryptoContext(client=self._bitwarden_client, stack=stack),
        )
        v = self._bitwarden_client._api_request(
            "POST", f"api/ciphers/{self.Id}/attachment/v2", json=ard
        ).json()
        self._bitwarden_client._api_request(
            "POST",
            "api" + v["url"],
            files={
                "data": (
                    ard["fileName"],
                    io.BytesIO(ed),
                    "application/octet-stream",
                )
            },
        )

    def uri_match(self, name: str) -> bool:
        return False

    def save(self):
        self._bitwarden_client.edit_item(self)


class LoginData(BitwardenBaseModel):
    username: SecretString | None = None
    password: SecretString | None = None
    passwordRevisionDate: datetime.datetime | None = None
    Uri: SecretString | None = None
    Uris: list[UriMatch] | None = None
    PasswordHistory: list[PasswordChange] | None = None
    response: str | None = None
    fido2Credentials: list[Fido2Credential] | None = None

    autofillOnPageLoad: bool | None = None
    totp: SecretString | None = None

    def uri_match(self, name: str) -> bool:
        if self.Uri and self.Uri == name:
            return True

        if self.Uris:
            for um in self.Uris:
                if um.uri_match(name):
                    return True
        return False


class Login(_CipherBase):
    Type: Literal[CipherType.Login] = CipherType.Login

    Login: LoginData | None = None  # type: ignore

    def uri_match(self, name: str) -> bool:
        if self.Login:
            return self.Login.uri_match(name)
        return False


class SecureNoteData(BitwardenBaseModel):
    Fields: list[XField] | None = None

    Notes: SecretString | None = None

    response: str | None = None
    type: int | None = None


class SecureNote(_CipherBase):
    Type: Literal[CipherType.SecureNote] = CipherType.SecureNote
    SecureNote: SecureNoteData | None = None  # type: ignore


class CardData(BitwardenBaseModel):
    Fields: list[XField] | None = None

    cardholderName: SecretString | None = None
    brand: SecretString | None = None
    code: SecretString | None = None
    expMonth: SecretString | None = None
    expYear: SecretString | None = None
    number: SecretString | None = None


class Card(_CipherBase):
    Type: Literal[CipherType.Card] = CipherType.Card
    Card: CardData | None = None  # type: ignore


class IdentityData(BitwardenBaseModel):
    Fields: list[XField] | None = None

    title: SecretString | None = None
    firstName: SecretString | None = None
    middleName: SecretString | None = None
    lastName: SecretString | None = None
    username: SecretString | None = None
    company: SecretString | None = None

    ssn: SecretString | None = None
    passportNumber: SecretString | None = None
    licenseNumber: SecretString | None = None

    email: SecretString | None = None
    phone: SecretString | None = None
    address1: SecretString | None = None
    address2: SecretString | None = None
    address3: SecretString | None = None
    city: SecretString | None = None
    state: SecretString | None = None
    postalCode: SecretString | None = None
    country: SecretString | None = None


class Identity(_CipherBase):
    Type: Literal[CipherType.Identity] = CipherType.Identity
    Identity: IdentityData = None  # type: ignore


class SSHKeyData(BitwardenBaseModel):
    keyFingerprint: SecretString | None = None
    privateKey: SecretString | None = None
    publicKey: SecretString | None = None


class SSHKey(_CipherBase):
    Type: Literal[CipherType.SSHKey] = CipherType.SSHKey
    sshKey: SSHKeyData = None  # type: ignore


CipherDetails = Annotated[
    Union[Login, SecureNote, Card, Identity, SSHKey],
    Field(discriminator="Type"),
]

CipherDetail: TypeAdapter[CipherDetails] = TypeAdapter(CipherDetails)


class CollectionAccess(BitwardenBaseModel):
    ReadOnly: bool = False
    HidePasswords: bool = False
    Manage: bool = False


class CollectionUser(CollectionAccess):
    CollectionId: UUID | None = Field(None, validate_default=True)
    UserId: UUID | None = Field(
        None,
        validation_alias=AliasChoices("id", "Id"),
        serialization_alias="id",
    )

    @field_validator("CollectionId")
    @classmethod
    def set_id(cls, v, info: ValidationInfo):
        if v is None and info.context is not None:
            ctx: CryptoContext = cast(CryptoContext, info.context)
            return ctx.parent_id
        return v


class UserCollection(CollectionAccess):
    CollectionId: UUID | None = Field(
        None,
        validation_alias=AliasChoices("id", "Id"),
        serialization_alias="id",
    )
    UserId: UUID | None = Field(None, validate_default=True)

    @field_validator("UserId")
    @classmethod
    def set_id(cls, v, info: ValidationInfo):
        if v is None and info.context is not None:
            ctx: CryptoContext = cast(CryptoContext, info.context)
            return ctx.parent_id
        return v


class OrganizationCollection(BitwardenBaseModel):
    Id: UUID | None = None
    OrganizationId: UUID | None = Field(None, validate_default=True)
    Name: SecretString
    ExternalId: str | None = None

    @field_validator("OrganizationId")
    @classmethod
    def set_id(cls, v, info: ValidationInfo):
        if v is None and info.context is not None:
            ctx: CryptoContext = cast(CryptoContext, info.context)
            return ctx.parent_id
        return v

    def users(self) -> list[CollectionUser]:
        resp = self.api_client.api_request(
            "GET",
            f"api/organizations/{self.OrganizationId}/collections/{self.Id}/users",
            params={"includeCollections": True, "includeGroups": True},
        )
        return TypeAdapter(list[CollectionUser]).validate_json(
            resp.text,
            context=CryptoContext(client=self.api_client, parent_id=self.Id),
        )

    def set_users(
        self,
        users: list[CollectionUser] | list[UUID],
        default_readonly: bool = False,
        default_hide_passwords: bool = False,
        default_manage: bool = False,
    ):
        users_payload = []
        if users is not None and len(users) > 0:
            if isinstance(users[0], CollectionUser):
                users = cast("list[CollectionUser]", users)
                users_payload = [
                    user.model_dump(
                        exclude={"CollectionId"}, by_alias=True, mode="json"
                    )
                    for user in users
                ]
            else:
                users = cast("list[UUID]", users)
                users_payload = [
                    {
                        "id": str(user_id),
                        "readOnly": default_readonly,
                        "hidePasswords": default_hide_passwords,
                        "manage": default_manage,
                    }
                    for user_id in users
                ]
        return self.api_client.api_request(
            "PUT",
            f"api/organizations/{self.OrganizationId}/collections/{self.Id}/users",
            json=users_payload,
        )

    # Delete collection
    def delete(self):
        return self.api_client.api_request(
            "DELETE",
            f"api/organizations/{self.OrganizationId}/collections/{self.Id}",
        )


class UserPublicKey(BitwardenBaseModel):
    """
    c.f. https://github.com/dani-garcia/vaultwarden/blob/d6a3d539ed13352085ca7dfa63c49017d86c419b/src/api/core/accounts.rs#L471

    """

    userId: UUID
    publicKey: RSAPublicKey
    object: Literal["userKey"]


class ConfirmData(BitwardenBaseModel):
    Id: UUID | None = None
    Key: SecretOrganizationKey | None

    @model_validator(mode="wrap")
    @classmethod
    def val_set_key(
        cls,
        data: Any,
        handler: ModelWrapValidatorHandler[Self],
        info: ValidationInfo,
    ) -> Self:
        return val_set_key(cls, data, handler, info)

    @model_serializer(mode="wrap")
    def ser_set_key(
        self, handler: SerializerFunctionWrapHandler, info: SerializationInfo
    ) -> Any:
        return ser_set_key(self, handler, info)


class OrganizationUserDetails(BitwardenBaseModel):
    Id: UUID | None = None
    Email: str
    UserId: UUID | None = None
    OrganizationId: UUID | None = Field(None, validate_default=True)
    Status: int
    Type: OrganizationUserType
    ExternalId: str | None
    Key: str | None = None
    ResetPasswordKey: str | None = None
    Collections: list[UserCollection]
    Groups: list | None = None
    TwoFactorEnabled: bool
    Permissions: dict[str, Any] | None = None

    @field_validator("OrganizationId")
    @classmethod
    def set_id(cls, v, info: ValidationInfo):
        if v is None and info.context is not None:
            ctx: CryptoContext = cast(CryptoContext, info.context)
            return ctx.parent_id
        return v

    def add_collections(self, collections: list[UUID]):
        _current_collections = [coll.CollectionId for coll in self.Collections]
        for collection in collections:
            if collection in _current_collections:
                continue
            user = UserCollection.model_construct(
                CollectionId=collection,
                UserId=self.Id,
                ReadOnly=False,
                HidePasswords=False,
                Manage=False,
            )
            user._bitwarden_client = self.api_client
            self.Collections.append(user)
        pl = self.model_dump(
            include={
                "Collections": {
                    "__all__": {
                        "CollectionId": True,
                        "ReadOnly": True,
                        "HidePasswords": True,
                        "Manage": True,
                    }
                },
                "Groups": True,
                "Type": True,
            },
            exclude={
                "Permissions": self.Permissions is None,
            },
            by_alias=True,
            mode="json",
        )
        return (
            self.api_client.api_request(
                "POST",
                f"api/organizations/{self.OrganizationId}/users/{self.Id}",
                json=pl,
            ),
        )

    # TODO add collections as list of CollectionUser
    def remove_collections(self, collections: list[UUID]):
        self.Collections = [
            coll
            for coll in self.Collections
            if coll.CollectionId not in collections
        ]
        pl = self.model_dump(
            include={
                "Collections": {
                    "__all__": {
                        "Id",
                        "CollectionId",
                        "ReadOnly",
                        "HidePasswords",
                        "Manage",
                    }
                },
                "Groups": True,
                "Type": True,
            },
            exclude={
                "Permissions": self.Permissions is None,
            },
            by_alias=True,
            mode="json",
        )
        return self.api_client.api_request(
            "POST",
            f"api/organizations/{self.OrganizationId}/users/{self.Id}",
            json=pl,
        )

    def update_collection(self, collections: list[UUID]):
        self.Collections = [
            UserCollection(
                UserId=self.Id,
                CollectionId=coll,
                ReadOnly=False,
                HidePasswords=False,
            )
            for coll in collections
        ]
        return self.api_client.api_request(
            "POST",
            f"api/organizations/{self.OrganizationId}/users/{self.Id}",
            json=self.model_dump(
                include={
                    "Collections": {
                        "__all__": {
                            "CollectionId",
                            "ReadOnly",
                            "HidePasswords",
                            "Manage",
                        }
                    },
                    "Groups": True,
                    "Type": True,
                },
                exclude={
                    "Permissions": self.Permissions is None,
                },
                by_alias=True,
                mode="json",
            ),
        )

    def publicKey(self) -> RSA.RsaKey:  # noqa: N802
        """
        c.f. https://github.com/dani-garcia/vaultwarden/blob/d6a3d539ed13352085ca7dfa63c49017d86c419b/src/api/core/accounts.rs#L471
        :return:
        """
        resp = self.api_client.api_request(
            "GET", f"api/users/{self.UserId}/public-key"
        )
        return UserPublicKey.model_validate_json(
            resp.text, context=CryptoContext(client=self.api_client)
        ).publicKey

    def delete(self):
        return self.api_client.api_request(
            "DELETE",
            f"api/organizations/{self.OrganizationId}/users/{self.Id}",
        )


class CollectionCipher(BitwardenBaseModel):
    CollectionId: UUID
    CipherId: UUID


class Organization(BitwardenBaseModel):
    Id: UUID | None = Field(None, validate_default=True)
    Name: str
    BillingEmail: str
    Object: str | None
    _collections: list[OrganizationCollection] | None = None
    _users: list[OrganizationUserDetails] | None = None
    _ciphers: list[CipherDetails] | None = None

    @field_validator("Id")
    @classmethod
    def set_id(cls, v, info: ValidationInfo):
        if v is None and info.context is not None:
            ctx: CryptoContext = cast(CryptoContext, info.context)
            return ctx.parent_id
        return v

    def rename(self, new_name: str):
        payload = {"name": new_name, "billingEmail": self.BillingEmail}
        resp = self.api_client.api_request(
            "PUT", f"api/organizations/{self.Id}", json=payload
        )
        self.Name = new_name
        return resp

    def invite(
        self,
        email,
        collections: (
            list[UserCollection]
            | list[OrganizationCollection]
            | list[UUID]
            | list[str]
            | None
        ) = None,
        user_type: OrganizationUserType = OrganizationUserType.User,
        permissions=None,
        groups: list[UUID] | None = None,
        default_readonly: bool = False,
        default_hide_passwords: bool = False,
        default_manage: bool = False,
    ):
        if permissions is None:
            permissions = {}
        if groups is None:
            groups = []
        collections_payload = []
        if collections is not None and len(collections) > 0:
            for coll in collections:
                if isinstance(coll, UserCollection):
                    coll = cast("UserCollection", coll)
                    ex: dict[str, Literal[True]] = {"UserId": True}
                    collections_payload.append(
                        coll.model_dump(
                            by_alias=True,
                            mode="json",
                            exclude=ex,
                        )
                    )
                else:
                    if isinstance(coll, OrganizationCollection):
                        coll = cast("OrganizationCollection", coll)
                        coll_id = str(coll.Id)
                    elif isinstance(coll, UUID):
                        coll = cast("UUID", coll)
                        coll_id = str(coll)
                    else:
                        coll_id = cast("str", coll)
                    collections_payload.append(
                        {
                            "id": coll_id,
                            "readOnly": default_readonly,
                            "hidePasswords": default_hide_passwords,
                            "manage": default_manage,
                        }
                    )

        payload = {
            "emails": [email],
            "type": user_type,
            "collections": collections_payload,
            "groups": groups,
            "permissions": permissions,
        }
        resp = self.api_client.api_request(
            "POST", f"api/organizations/{self.Id}/users/invite", json=payload
        )
        self._users = self._get_users()
        return resp

    def confirm(self, user: OrganizationUserDetails):
        """
        c.f. https://github.com/dani-garcia/vaultwarden/blob/d6a3d539ed13352085ca7dfa63c49017d86c419b/src/api/core/organizations.rs#L1382
        :param new_user:
        :return:
        """

        publicKey = user.publicKey()  # noqa: N806

        confirm = ConfirmData.model_construct(Key=self.key())
        payload = confirm.model_dump(
            mode="json",
            by_alias=True,
            context=CryptoContext(client=self.api_client, stack=[publicKey]),
        )
        resp = self.api_client.api_request(
            "POST",
            f"api/organizations/{self.Id}/users/{user.Id}/confirm",
            json=payload,
        )
        return resp

    def _get_users(self) -> list[OrganizationUserDetails]:
        resp = self.api_client.api_request(
            "GET",
            f"api/organizations/{self.Id}/users",
            params={"includeCollections": True, "includeGroups": True},
        )
        return (
            ResplistBitwarden[OrganizationUserDetails]
            .model_validate_json(
                resp.text,
                context=CryptoContext(
                    client=self.api_client, parent_id=self.Id
                ),
            )
            .Data
        )

    def users(
        self,
        force_refresh: bool = False,
        mfa: bool | None = None,
        search: str | UUID | None = None,
    ) -> list[OrganizationUserDetails]:
        if self._users is None or force_refresh:
            self._users = self._get_users()
        res = self._users
        if mfa is not None:
            res = [
                user for user in self._users if user.TwoFactorEnabled == mfa
            ]
        if search:
            for user in res:
                if search == user.Email or search == user.Id:
                    return [user]
            return []
        return res

    def user(self, user_id: UUID) -> OrganizationUserDetails:
        resp = self.api_client.api_request(
            "GET",
            f"api/organizations/{self.Id}/users/{user_id}",
            params={"includeCollections": True, "includeGroups": True},
        )
        return OrganizationUserDetails.model_validate_json(
            resp.text,
            context=CryptoContext(client=self.api_client, parent_id=self.Id),
        )

    def user_search(
        self,
        email: str,
        mfa: bool | None = None,
        force_refresh: bool = False,
    ) -> OrganizationUserDetails | None:
        users = self.users(search=email, mfa=mfa, force_refresh=force_refresh)
        if len(users) == 0:
            return None
        return users[0]

    def _get_collections(self) -> list[OrganizationCollection]:
        resp = self.api_client.api_request(
            "GET", f"api/organizations/{self.Id}/collections"
        )
        res = ResplistBitwarden[OrganizationCollection].model_validate_json(
            resp.text,
            context=CryptoContext(
                client=self.api_client, parent_id=self.Id, stack=[self.key()]
            ),
        )
        return res.Data

    def collections(
        self, force_refresh: bool = False, as_dict: bool = False
    ) -> list[OrganizationCollection] | dict[str, OrganizationCollection]:
        if self._collections is None or force_refresh:
            self._collections = self._get_collections()
        if as_dict:
            return {coll.Name: coll for coll in self._collections}
        return self._collections

    def create_collection(self, name: str) -> OrganizationCollection:
        org_key = self.key()
        data = {
            "name": SymmetricCipher.encode(
                name.encode("utf-8"), org_key
            ).decode("utf-8"),
            "groups": [],
            "users": [],
        }
        resp = self.api_client.api_request(
            "POST", f"api/organizations/{self.Id}/collections", json=data
        )
        res = OrganizationCollection.model_validate_json(
            resp.text,
            context=CryptoContext(
                client=self.api_client, parent_id=self.Id, stack=[org_key]
            ),
        )
        if self._collections is not None:
            self._collections.append(res)
        else:
            self._collections = [res]
        return res

    def delete_collection(self, collection_id: UUID):
        resp = self.api_client.api_request(
            "DELETE",
            f"api/organizations/{self.Id}/collections/{collection_id}",
        )
        self._collections = self._get_collections()
        return resp

    def collection(self, name) -> OrganizationCollection | None:
        self.collections()
        if self._collections is None:
            return None
        for collection in self._collections:
            if collection.Name == name:
                return collection
        return None

    def _get_ciphers(self) -> list[CipherDetails]:
        resp = self.api_client.api_request(
            "GET",
            "api/ciphers/organization-details",
            params={"organizationId": self.Id},
        )
        res = ResplistBitwarden[CipherDetails].model_validate_json(
            resp.text,
            context=CryptoContext(client=self.api_client, parent_id=self.Id),
        )
        return res.Data

    def ciphers(
        self, collection: UUID | None = None, force_refresh: bool = False
    ) -> list[CipherDetails]:
        """
        Get all ciphers for an organization
        :param collection: get ciphers for a specific collection
        :param force_refresh: force a refresh of the ciphers
        :return:
        """
        if self._ciphers is None or force_refresh:
            self._ciphers = self._get_ciphers()
        if collection is not None:
            return [
                cipher
                for cipher in self._ciphers
                if collection in cipher.CollectionIds
            ]
        return self._ciphers

    def key(self) -> bytes:
        for force_refresh in [False, True]:
            sync = self.api_client.sync(force_refresh=force_refresh)
            for org in sync.Profile.Organizations:
                if org.Id == self.Id:
                    assert org and org.Key
                    return org.Key
        else:
            raise BitwardenError(f"No Organizations `{self.Id}` found")

    def delete(self) -> None:
        self.api_client.api_request(
            "DELETE",
            f"api/organizations/{self.Id}",
            json=dict(
                masterPasswordHash=self._bitwarden_client.masterPasswordHash
            ),
        )


def get_organization(
    bitwarden_client: "BitwardenAPIClient", organisation_id: UUID | str
) -> Organization:
    oid = (
        UUID(organisation_id)
        if isinstance(organisation_id, str)
        else organisation_id
    )

    if bitwarden_client._sync is not None:
        for org in bitwarden_client._sync.Profile.Organizations:
            if org.Id == oid:
                r = Organization.model_construct(
                    Id=org.Id, Name=org.Name, BillingEmail="", Object=""
                )
                r._bitwarden_client = bitwarden_client
                return r

    resp = bitwarden_client.api_request(
        "GET", f"api/organizations/{organisation_id}"
    )
    return Organization.model_validate_json(
        resp.text,
        context=CryptoContext(client=bitwarden_client, parent_id=oid),
    )


class Kdf(PermissiveBaseModel):
    Kdf: int
    KdfIterations: int | None = None
    KdfMemory: int | None = None
    KdfParallelism: int | None = None

    @classmethod
    def argon2id(cls):
        return cls.model_construct(
            Kdf=KdfType.Argon2id,
            KdfMemory=32,
            KdfIterations=6,
            KdfParallelism=4,
        )


class KeysData(BitwardenBaseModel):
    encryptedPrivateKey: str
    publicKey: str


class RegisterData(BitwardenBaseModel):
    """
    c.f. https://bitwarden.com/help/bitwarden-security-white-paper/
    """

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    email: str
    password: str = Field(exclude=True)

    name: str
    Kdf: int
    #    key: str

    KdfIterations: int | None = None
    KdfMemory: int | None = None
    KdfParallelism: int | None = None

    #    keys: KeysData | None = None

    masterPasswordHint: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def masterPasswordHash(self) -> str:  # noqa: N802
        return masterPasswordHash(self._masterKey, self.password)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def key(self) -> str:
        return SymmetricCipher.encode(self._rawKey, self._masterKey).decode()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def keys(self) -> KeysData:
        return KeysData.model_construct(
            encryptedPrivateKey=SymmetricCipher.encode(
                self._rawKeys.exportKey("DER", pkcs=8), self._rawKey
            ).decode(),
            publicKey=base64.b64encode(
                self._rawKeys.publickey().exportKey("DER")
            ).decode(),
        )

    @cached_property
    def _masterKey(self) -> bytes:  # noqa: N802
        return make_master_key(
            self.password,
            self.email,
            Kdf.model_construct(
                Kdf=self.Kdf,
                KdfIterations=self.KdfIterations,
                KdfMemory=self.KdfMemory,
                KdfParallelism=self.KdfParallelism,
            ),
        )

    @cached_property
    def _stretchedKey(self) -> bytes:  # noqa: N802
        return stretch_key(self._masterKey)

    @cached_property
    def _rawKey(self) -> bytes:  # noqa: N802
        return token_bytes(64)

    @cached_property
    def _rawKeys(self) -> RSA.RsaKey:  # noqa: N802
        return RSA.generate(2048)


class OrgData(BitwardenBaseModel):
    """
    c.f. https://github.com/dani-garcia/vaultwarden/blob/d6a3d539ed13352085ca7dfa63c49017d86c419b/src/api/core/organizations.rs#L109-L119
    """

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    BillingEmail: str
    CollectionName: SecretString
    Key: SecretOrganizationKey
    Name: str
    # Keys: KeysData
    PlanType: int | str

    @computed_field(alias="keys")  # type: ignore[prop-decorator]
    @property
    def Keys(self) -> KeysData:  # noqa: N802
        return KeysData.model_construct(
            encryptedPrivateKey=SymmetricCipher.encode(
                self._rawKeys.exportKey("DER", pkcs=8), self.Key
            ).decode(),
            publicKey=base64.b64encode(
                self._rawKeys.publickey().exportKey("DER")
            ).decode(),
        )

    @cached_property
    def _rawKeys(self) -> RSA.RsaKey:  # noqa: N802
        return RSA.generate(2048)

    @model_serializer(mode="wrap")
    def ser_set_key(
        self, handler: SerializerFunctionWrapHandler, info: SerializationInfo
    ) -> Any:
        return ser_set_key(self, handler, info)
