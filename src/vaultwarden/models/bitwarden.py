from datetime import datetime
from typing import TypeVar, Generic, Iterator
from uuid import UUID

from bitwardentools.crypto import decrypt, encrypt
from pydantic import BaseModel, TypeAdapter, field_validator, Field
from pydantic_core.core_schema import ValidationInfo, FieldValidationInfo

from vaultwarden.clients.bitwarden import BitwardenClient
from vaultwarden.models.enum import CipherType, OrganizationUserType
from vaultwarden.models.exception_models import BitwardenError

# Pydantic models for Bitwarden data structures

T = TypeVar("T", bound="BitwardenBaseModel")


class ResplistBitwarden(BaseModel, Generic[T]):
    Data: list[T]


class BitwardenBaseModel(
    BaseModel, extra="allow", arbitrary_types_allowed=True
):
    bitwarden_client: BitwardenClient | None = Field(
        default=None, validate_default=True, exclude=True
    )

    @field_validator("bitwarden_client")
    @classmethod
    def set_client(cls, v, info: FieldValidationInfo):
        if v is None and info.context is not None:
            return info.context.get("client")
        return v


class CipherDetails(BitwardenBaseModel):
    Id: UUID | None = None
    OrganizationId: UUID | None = Field(None, validate_default=True)
    Type: CipherType
    Name: str
    CollectionIds: list[UUID] | None = []

    @field_validator("OrganizationId")
    @classmethod
    def set_id(cls, v, info: FieldValidationInfo):
        if v is None:
            return info.context.get("parent_id")
        return v

    def add_collections(self, collections: list[UUID]):
        _current_collections = self.CollectionIds
        for collection in collections:
            if collection in _current_collections:
                continue
            self.CollectionIds.append(collection)
        return self.bitwarden_client.api_request(
            "POST",
            f"api/ciphers/{self.Id}",
            json=self.model_dump(
                include={
                    "CollectionIds": True,
                }
            ),
        )

    def remove_collections(self, collections: list[UUID]):
        self.CollectionIds = [
            coll for coll in self.CollectionIds if coll not in collections
        ]
        return self.bitwarden_client.api_request(
            "POST",
            f"api/ciphers/{self.Id}",
            json=self.model_dump(
                include={
                    "CollectionIds": True,
                }
            ),
        )

    def delete(self):
        return self.bitwarden_client.api_request(
            "DELETE", f"api/ciphers/{self.Id}"
        )

    def update_collection(self, collections: list[UUID]):
        self.CollectionIds = collections
        return self.bitwarden_client.api_request(
            "POST",
            f"api/ciphers/{self.Id}",
            json=self.model_dump(
                include={
                    "CollectionIds": True,
                }
            ),
        )


class CollectionAccess(BitwardenBaseModel):
    ReadOnly: bool = False
    HidePasswords: bool = False


class CollectionUser(CollectionAccess):
    CollectionId: UUID | None = Field(None, validate_default=True)
    UserId: UUID | None = Field(None, alias="Id", serialization_alias="Id")

    @field_validator("CollectionId")
    @classmethod
    def set_id(cls, v, info: FieldValidationInfo):
        if v is None:
            return info.context.get("parent_id")
        return v


class UserCollection(CollectionAccess):
    CollectionId: UUID | None = Field(
        None, alias="Id", serialization_alias="Id"
    )
    UserId: UUID | None = Field(None, validate_default=True)

    @field_validator("UserId")
    @classmethod
    def set_id(cls, v, info: FieldValidationInfo):
        if v is None:
            return info.context.get("parent_id")
        return v


class OrganizationUser(BitwardenBaseModel):
    Id: UUID | None = None
    UserId: UUID | None = None
    OrganizationId: UUID | None = Field(None, validate_default=True)
    Status: int
    Type: int
    AccessAll: bool
    ExternalId: str | None
    Key: str | None = None
    ResetPasswordKey: str | None = None

    @field_validator("OrganizationId")
    @classmethod
    def set_id(cls, v, info: FieldValidationInfo):
        if v is None:
            return info.context.get("parent_id")
        return v


class OrganizationCollection(BitwardenBaseModel):
    Id: UUID | None = None
    OrganizationId: UUID | None = Field(None, validate=True)
    Name: str
    ExternalId: str | None

    @field_validator("OrganizationId")
    @classmethod
    def set_id(cls, v, info: FieldValidationInfo):
        if v is None:
            return info.context.get("parent_id")
        return v

    def users(self) -> list[CollectionUser]:
        resp = self.bitwarden_client.api_request(
            "GET",
            f"api/organizations/{self.OrganizationId}/collections/{self.Id}/users",
            params={"includeCollections": True, "includeGroups": True},
        )
        return TypeAdapter(list[CollectionUser]).validate_json(
            resp.text,
            context={"parent_id": self.Id, "client": self.bitwarden_client},
        )

    def set_users(
        self,
        users: list[CollectionUser] | list[UUID],
        default_readonly: bool = False,
        default_hide_passwords: bool = False,
    ):
        users_payload = []
        if users is not None and len(users) > 0:
            if isinstance(users[0], CollectionUser):
                users_payload = [
                    user.model_dump(
                        exclude={"CollectionId"}, by_alias=True, mode="json"
                    )
                    for user in users
                ]
            else:
                users_payload = [
                    {
                        "id": str(user_id),
                        "readOnly": default_readonly,
                        "hidePasswords": default_hide_passwords,
                    }
                    for user_id in users
                ]
        return self.bitwarden_client.api_request(
            "PUT",
            f"api/organizations/{self.OrganizationId}/collections/{self.Id}/users",
            json=users_payload,
        )

    # Delete collection
    def delete(self):
        return self.bitwarden_client.api_request(
            "DELETE",
            f"api/organizations/{self.OrganizationId}/collections/{self.Id}",
        )


class OrganizationUserDetails(OrganizationUser):
    Collections: list[UserCollection]
    Groups: list = []
    TwoFactorEnabled: bool

    _collections: list[OrganizationCollection] = None

    def add_collections(self, collections: list[UUID]):
        _current_collections = [coll.CollectionId for coll in self.Collections]
        for collection in collections:
            if collection in _current_collections:
                continue
            user = UserCollection(
                Id=collection,
                UserId=self.Id,
                ReadOnly=False,
                HidePasswords=False,
            )
            user.bitwarden_client = self.bitwarden_client
            self.Collections.append(user)
        pl = self.model_dump(
            include={
                "Collections": {
                    "__all__": {
                        "CollectionId": True,
                        "ReadOnly": True,
                        "HidePasswords": True,
                    }
                },
                "Groups": True,
                "Type": True,
                "AccessAll": True,
            },
            by_alias=True,
            mode="json",
        )
        return (
            self.bitwarden_client.api_request(
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
                    }
                },
                "Groups": True,
                "Type": True,
                "AccessAll": True,
            },
            by_alias=True,
            mode="json",
        )
        return self.bitwarden_client.api_request(
            "POST",
            f"api/organizations/{self.OrganizationId}/users/{self.Id}",
            json=pl,
        )

    def update_collection(self, collections: list[UUID]):
        self.Collections = [
            UserCollection(
                CollectionId=coll,
                UserId=self.Id,
                ReadOnly=False,
                HidePasswords=False,
            )
            for coll in collections
        ]
        return self.bitwarden_client.api_request(
            "POST",
            f"api/organizations/{self.OrganizationId}/users/{self.Id}",
            json=self.model_dump(
                include={
                    "Collections": {
                        "__all__": {
                            "CollectionId",
                            "ReadOnly",
                            "HidePasswords",
                        }
                    },
                    "Groups": True,
                    "Type": True,
                    "AccessAll": True,
                },
                by_alias=True,
                mode="json",
            ),
        )

    def delete(self):
        return self.bitwarden_client.api_request(
            "DELETE",
            f"api/organizations/{self.OrganizationId}/users/{self.Id}",
        )


class CollectionCipher(BitwardenBaseModel):
    CollectionId: UUID
    CipherId: UUID


class Organization(BitwardenBaseModel):
    Id: UUID | None = Field(None, validate=True)
    Name: str
    Object: str | None
    _collections: list[OrganizationCollection] = None
    _users: list[OrganizationUser] = None
    _ciphers: list[CipherDetails] = None

    @field_validator("Id")
    @classmethod
    def set_id(cls, v, info: FieldValidationInfo):
        if v is None:
            return info.context.get("parent_id")
        return v

    def invite(
        self,
        email,
        collections: list[UUID] | list[UserCollection] | None = None,
        access_all: bool = False,
        user_type: OrganizationUserType = OrganizationUserType.User,
        default_readonly: bool = False,
        default_hide_passwords: bool = False,
    ):
        collections_payload = []
        if collections is not None and len(collections) > 0:
            if isinstance(collections[0], UserCollection):
                collections_payload = [
                    coll.model_dump(exclude={"UserId"}, by_alias=True)
                    for coll in collections
                ]
                collections_payload = TypeAdapter(
                    list[UserCollection]
                ).dump_python(
                    collections,
                    mode="json",
                    by_alias=True,
                    exclude={-1: {"UserId"}},
                )
            else:
                collections_payload = [
                    {
                        "id": collection_id,
                        "readOnly": default_readonly,
                        "hidePasswords": default_hide_passwords,
                    }
                    for collection_id in collections
                ]

        payload = {
            "email": [email],
            "accessAll": access_all,
            "type": user_type,
            "Collections": collections_payload,
            "Groups": [],
        }
        return self.bitwarden_client.api_request(
            "POST", f"api/organizations/{self.Id}/users/invite", json=payload
        )

    def _get_users(self) -> list[OrganizationUser]:
        resp = self.bitwarden_client.api_request(
            "GET",
            f"api/organizations/{self.Id}/users",
            params={"includeCollections": True, "includeGroups": True},
        )
        return (
            ResplistBitwarden[OrganizationUser]
            .model_validate_json(
                resp.text,
                context={
                    "parent_id": self.Id,
                    "client": self.bitwarden_client,
                },
            )
            .Data
        )

    def users(
        self, force_refresh: bool = False, mfa: bool = None
    ) -> list[OrganizationUser]:
        if self._users is None or force_refresh:
            self._users = self._get_users()
        if mfa is not None:
            return [
                user for user in self._users if user.TwoFactorEnabled == mfa
            ]
        return self._users

    def user_details(self, user_id: UUID) -> OrganizationUserDetails:
        resp = self.bitwarden_client.api_request(
            "GET",
            f"api/organizations/{self.Id}/users/{user_id}",
            params={"includeCollections": True, "includeGroups": True},
        )
        return OrganizationUserDetails.model_validate_json(
            resp.text,
            context={"parent_id": self.Id, "client": self.bitwarden_client},
        )

    def _get_collections(self) -> list[OrganizationCollection]:
        resp = self.bitwarden_client.api_request(
            "GET", f"api/organizations/{self.Id}/collections"
        )
        res = ResplistBitwarden[OrganizationCollection].model_validate_json(
            resp.text,
            context={"parent_id": self.Id, "client": self.bitwarden_client},
        )
        org_key = self.key()
        # map each collection name to the decrypted name
        for collection in res.Data:
            collection.Name = decrypt(collection.Name, org_key).decode("utf-8")
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
            "Name": encrypt(2, name, self.key()),
            "Groups": [],
            "Users": [],
        }
        resp = self.bitwarden_client.api_request(
            "POST", f"api/organizations/{self.Id}/collections", json=data
        )
        res = OrganizationCollection.model_validate_json(
            resp.text,
            context={"parent_id": self.Id, "client": self.bitwarden_client},
        )
        res.Name = decrypt(res.Name, org_key).decode("utf-8")
        self._collections.append(res)
        return res

    def delete_collection(self, collection_id: UUID):
        resp = self.bitwarden_client.api_request(
            "DELETE",
            f"api/organizations/{self.Id}/collections/{collection_id}",
        )
        self._collections = self._get_collections()
        return resp

    def collection(self, name) -> OrganizationCollection | None:
        self.collections()
        for collection in self._collections:
            if collection.Name == name:
                return collection
        return None

    def _get_ciphers(self) -> list[CipherDetails]:
        resp = self.bitwarden_client.api_request(
            "GET",
            f"api/ciphers/organization-details",
            params={"organizationId": self.Id},
        )
        res = ResplistBitwarden[CipherDetails].model_validate_json(
            resp.text,
            context={"parent_id": self.Id, "client": self.bitwarden_client},
        )
        org_key = self.key()
        # map each cipher name to the decrypted name
        for cipher in res.Data:
            cipher.Name = decrypt(cipher.Name, org_key).decode("utf-8")
        return res.Data

    def ciphers(
        self, collection: UUID = None, force_refresh: bool = False
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

    def key(self):
        sync = self.bitwarden_client.get_sync()
        profile = sync.get("Profile", None)
        if profile is None:
            raise BitwardenError("No profile in Sync")
        orgs = profile.get("Organizations", None)
        if orgs is None:
            raise BitwardenError("No Organizations in Sync[Profile]")
        raw_key = None
        for org in orgs:
            if UUID(org.get("Id")) == self.Id:
                raw_key = org.get("Key")
                break
        if raw_key is not None:
            return decrypt(
                raw_key, self.bitwarden_client.api_token.get("orgs_key")
            )
        raise BitwardenError(f"No Organizations `{self.Id}` found")


class BitwardenUser(BitwardenBaseModel):
    AvatarColor: str | None
    CreatedAt: datetime | None
    Culture: str
    Email: str
    EmailVerified: bool
    ForcePasswordReset: bool
    Id: UUID | None = None
    Key: str
    MasterPasswordHint: str | None
    Name: str
    Object: str | None
    Organizations: list[OrganizationUser] = []
    TwoFactorEnabled: bool
    UserEnabled: bool
    _Status: int | None = None
