from typing import Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, Field, TypeAdapter, field_validator
from pydantic_core.core_schema import FieldValidationInfo

from vaultwarden.clients.bitwarden import BitwardenAPIClient
from vaultwarden.models.enum import CipherType, OrganizationUserType
from vaultwarden.models.exception_models import BitwardenError
from vaultwarden.utils.crypto import decrypt, encrypt

# Pydantic models for Bitwarden data structures

T = TypeVar("T", bound="BitwardenBaseModel")


class ResplistBitwarden(BaseModel, Generic[T]):
    Data: list[T]


class BitwardenBaseModel(
    BaseModel, extra="allow", arbitrary_types_allowed=True
):
    bitwarden_client: BitwardenAPIClient | None = Field(
        default=None, validate_default=True, exclude=True
    )

    @field_validator("bitwarden_client")
    @classmethod
    def set_client(cls, v, info: FieldValidationInfo):
        if v is None and info.context is not None:
            return info.context.get("client")
        return v

    @property
    def api_client(self) -> BitwardenAPIClient:
        assert self.bitwarden_client is not None
        return self.bitwarden_client


class CipherDetails(BitwardenBaseModel):
    Id: UUID | None = None
    OrganizationId: UUID | None = Field(None, validate_default=True)
    Type: CipherType
    Name: str
    CollectionIds: list[UUID]

    @field_validator("OrganizationId")
    @classmethod
    def set_id(cls, v, info: FieldValidationInfo):
        if v is None and info.context is not None:
            return info.context.get("parent_id")
        return v

    def add_collections(self, collections: list[UUID]):
        _current_collections = self.CollectionIds
        for collection in collections:
            if collection in _current_collections:
                continue
            self.CollectionIds.append(collection)
        return self.api_client.api_request(
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
        return self.api_client.api_request(
            "POST",
            f"api/ciphers/{self.Id}",
            json=self.model_dump(
                include={
                    "CollectionIds": True,
                }
            ),
        )

    def delete(self):
        return self.api_client.api_request("DELETE", f"api/ciphers/{self.Id}")

    def update_collection(self, collections: list[UUID]):
        self.CollectionIds = collections
        return self.api_client.api_request(
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
        if v is None and info.context is not None:
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
        if v is None and info.context is not None:
            return info.context.get("parent_id")
        return v


class OrganizationCollection(BitwardenBaseModel):
    Id: UUID | None = None
    OrganizationId: UUID | None = Field(None, validate_default=True)
    Name: str
    ExternalId: str | None

    @field_validator("OrganizationId")
    @classmethod
    def set_id(cls, v, info: FieldValidationInfo):
        if v is None and info.context is not None:
            return info.context.get("parent_id")
        return v

    def users(self) -> list[CollectionUser]:
        resp = self.api_client.api_request(
            "GET",
            f"api/organizations/{self.OrganizationId}/collections/{self.Id}/users",
            params={"includeCollections": True, "includeGroups": True},
        )
        return TypeAdapter(list[CollectionUser]).validate_json(
            resp.text,
            context={"parent_id": self.Id, "client": self.api_client},
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
                    user.model_dump(  # type: ignore
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


class OrganizationUserDetails(BitwardenBaseModel):
    Id: UUID | None = None
    Email: str
    UserId: UUID | None = None
    OrganizationId: UUID | None = Field(None, validate_default=True)
    Status: int
    Type: OrganizationUserType
    AccessAll: bool
    ExternalId: str | None
    Key: str | None = None
    ResetPasswordKey: str | None = None
    Collections: list[UserCollection]
    Groups: list | None = None
    TwoFactorEnabled: bool

    @field_validator("OrganizationId")
    @classmethod
    def set_id(cls, v, info: FieldValidationInfo):
        if v is None and info.context is not None:
            return info.context.get("parent_id")
        return v

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
            user.bitwarden_client = self.api_client
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
                    }
                },
                "Groups": True,
                "Type": True,
                "AccessAll": True,
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
                Id=coll,
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
    Object: str | None
    _collections: list[OrganizationCollection] | None = None
    _users: list[OrganizationUserDetails] | None = None
    _ciphers: list[CipherDetails] | None = None

    @field_validator("Id")
    @classmethod
    def set_id(cls, v, info: FieldValidationInfo):
        if v is None and info.context is not None:
            return info.context.get("parent_id")
        return v

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
        access_all: bool = False,
        user_type: OrganizationUserType = OrganizationUserType.User,
        default_readonly: bool = False,
        default_hide_passwords: bool = False,
    ):
        collections_payload = []
        if collections is not None and len(collections) > 0:
            assert collections is not None
            for coll in collections:
                if isinstance(coll, UserCollection):
                    assert isinstance(coll, UserCollection)
                    collections_payload.append(
                        coll.model_dump(
                            by_alias=True,
                            mode="json",
                            exclude={"UserId": True},
                        )
                    )
                else:
                    coll_id = ""
                    if isinstance(coll, OrganizationCollection):
                        assert isinstance(coll, OrganizationCollection)
                        coll_id = str(coll.Id)
                    elif isinstance(collections[0], UUID):
                        assert isinstance(coll, UUID)
                        coll_id = str(coll)
                    else:
                        assert isinstance(coll, str)
                        coll_id = coll
                    collections_payload.append(
                        {
                            "id": coll_id,
                            "readOnly": default_readonly,
                            "hidePasswords": default_hide_passwords,
                        }
                    )

        payload = {
            "emails": [email],
            "accessAll": access_all,
            "type": user_type,
            "Collections": collections_payload,
            "Groups": [],
        }
        resp = self.api_client.api_request(
            "POST", f"api/organizations/{self.Id}/users/invite", json=payload
        )
        self._users = self._get_users()
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
                context={
                    "parent_id": self.Id,
                    "client": self.api_client,
                },
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
            context={"parent_id": self.Id, "client": self.api_client},
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
            context={"parent_id": self.Id, "client": self.api_client},
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
        resp = self.api_client.api_request(
            "POST", f"api/organizations/{self.Id}/collections", json=data
        )
        res = OrganizationCollection.model_validate_json(
            resp.text,
            context={"parent_id": self.Id, "client": self.api_client},
        )
        res.Name = decrypt(res.Name, org_key).decode("utf-8")
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
            context={"parent_id": self.Id, "client": self.api_client},
        )
        org_key = self.key()
        # map each cipher name to the decrypted name
        for cipher in res.Data:
            cipher.Name = decrypt(cipher.Name, org_key).decode("utf-8")
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

    def key(self):
        sync = self.api_client.sync()
        raw_key = None
        for org in sync.Profile.Organizations:
            if org.Id == self.Id:
                raw_key = org.Key
                break
        if raw_key is not None:
            return decrypt(raw_key, self.api_client.connect_token.orgs_key)
        raise BitwardenError(f"No Organizations `{self.Id}` found")


def get_organization(
    bitwarden_client, organisation_id: UUID | str
) -> Organization:
    resp = bitwarden_client.api_request(
        "GET", f"api/organizations/{organisation_id}"
    )
    return Organization.model_validate_json(
        resp.text,
        context={"client": bitwarden_client, "parent_id": organisation_id},
    )
