# Class Bitwarden client with a httpx client
from typing import Any, List, Literal, Optional
from uuid import UUID

from bitwardentools import caseinsentive_key_search
from bitwardentools.crypto import decrypt, encrypt, make_master_key
from httpx import Client, HTTPError, Response

from vaultwarden.models.api_models import ApiToken
from vaultwarden.models.exception_models import BitwardenError
from vaultwarden.utils.logger import logger
from vaultwarden.utils.tools import (
    get_collection_id_from_ditcs,
    get_matching_ids_from_ditcs,
    log_raise_for_status,
)


class BitwardenClient:
    def __init__(
        self,
        url: str,
        email: str,
        password: str,
        client_id: str,
        client_secret: str,
        device_id: UUID | str,
    ):
        # if one of the parameters is None, raise an exception
        if not all(
            [url, email, password, client_id, client_secret, device_id]
        ):
            raise BitwardenError("All parameters are required")
        self.email = email
        self.password = password
        self.client_id = client_id
        self.client_secret = client_secret
        self.device_id = device_id
        self.url = url.strip("/")
        self._http_client = Client(
            base_url=f"{self.url}/",
            event_hooks={"response": [log_raise_for_status]},
        )
        self._api_token: Optional[ApiToken] = None
        self.sync = None

    @property
    def api_token(self) -> ApiToken:
        assert self._api_token is not None
        return self._api_token

    @api_token.setter
    def api_token(self, value: ApiToken):
        self._api_token = value

    # refresh api token if expired
    def _refresh_api_token(self) -> None:
        headers = {
            "content-type": "application/x-www-form-urlencoded; charset=utf-8",
        }
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": f"{self.api_token.token.get('refresh_token')}",
        }
        resp = self._http_client.post(
            "identity/connect/token", headers=headers, data=payload
        )
        json_resp = resp.json()

        self.api_token.refresh(json_resp)

    # login to api
    def _api_login(self) -> None:
        if self._api_token and not self.api_token.is_expired():
            return

        if self._api_token and self.api_token.is_expired():
            self._refresh_api_token()
            return

        headers = {
            "content-type": "application/x-www-form-urlencoded; charset=utf-8",
        }
        payload = {
            "grant_type": "client_credentials",
            "client_secret": f"{self.client_secret}",
            "client_id": f"{self.client_id}",
            "scope": "api",
            # 21 for "SDK", see https://github.com/bitwarden/server/blob/master/src/Core/Enums/DeviceType.cs
            "deviceType": 21,
            "deviceIdentifier": f"{self.device_id}",
            "deviceName": "python-vaultwarden",
        }
        resp = self._http_client.post(
            "identity/connect/token", headers=headers, data=payload
        )
        json_resp = resp.json()
        master_key = make_master_key(
            password=self.password,
            salt=self.email,
            iterations=caseinsentive_key_search(json_resp, "KdfIterations"),
        )
        self._api_token = ApiToken(
            json_resp, master_key, json_resp["expires_in"]
        )

    def _api_request(
        self,
        method: Literal["GET", "POST", "DELETE", "PUT"],
        path: str,
        **kwargs: Any,
    ) -> Response:
        self._api_login()
        headers = {
            "Authorization": f"Bearer {self.api_token.bearer()}",
            "content-type": "application/json; charset=utf-8",
            "Accept": "*/*",
        }
        return self._http_client.request(
            method, path, headers=headers, **kwargs
        )

    def get_sync(self):
        if self.sync is None:
            resp = self._api_request("GET", "api/sync")
            self.sync = resp.json()
        return self.sync

    # Organization Management
    def get_organization_user_details(
        self, organization_id: str, user_org_id: str
    ):
        return self._api_request(
            "GET",
            f"api/organizations/{organization_id}/users/{user_org_id}",
            params={"includeCollections": True, "includeGroups": True},
        ).json()

    # Get all users in an organization. Returns a dict with email as key and
    # user details as value. If raw is True, returns the raw json response
    def get_organization_users(self, organization_id: str, raw=False):
        users = (
            self._api_request(
                "GET",
                f"api/organizations/{organization_id}/users",
                params={"includeCollections": True, "includeGroups": True},
            )
            .json()
            .get("Data")
        )
        if raw:
            return users
        return {u["Email"]: u for u in users}

    def get_org_key(self, org_id):
        sync = self.get_sync()
        profile = sync.get("Profile", None)
        if profile is None:
            raise BitwardenError("No profile in Sync")
        orgs = profile.get("Organizations", None)
        if orgs is None:
            raise BitwardenError("No Organizations in Sync[Profile]")
        raw_key = None
        for org in orgs:
            if org.get("Id") == org_id:
                raw_key = org.get("Key")
                break
        if raw_key is not None:
            return decrypt(raw_key, self.api_token.get("orgs_key"))
        raise BitwardenError(f"No Organizations `{org_id}` found")

    def deduplicate_collection(self, organization_id):
        """
        Deduplicate collections with the same name in a given org, by moving
        users and secrets into the bigger (by user count) collection
        """
        collections = self.get_organization_collections(organization_id)

        seen_names = {}
        duplicated = {}
        # List duplicated collections, indexed on the name, referencing a
        # list of collections id
        for name, collection in collections:
            if seen_names.get(name) is None:
                seen_names[name] = collection["Id"]
            else:
                if duplicated.get(name) is None:
                    duplicated[name] = [seen_names[name]]
                duplicated[name].append(collection["Id"])

        # Loop over duplicated collection
        for id_list in duplicated.values():
            base_id = None
            nb_users = 0
            users = {}
            # Building user list by merging all accesses and choose which
            # collection will not be deleted (based on most users)
            for collection_id in id_list:
                coll_users = self.get_users_of_collection(
                    organization_id, collection_id
                )
                if len(coll_users.values()) >= nb_users:
                    base_id = collection_id
                    nb_users = len(coll_users.values())
                users |= coll_users

            users_list = list(users.values())

            # Removing the chosen collection from the list of collection to
            # delete
            id_list.remove(base_id)
            self.set_users_of_collection(organization_id, base_id, users_list)

            for collection_id in id_list:
                # List items inside the current collection and move these
                # items to the chosen collection
                ciphers = self.get_organizations_collection_items(
                    organization_id, collection_id
                )
                for cipher in ciphers:
                    cipher_collections = set(cipher.get("CollectionIds"))
                    cipher_collections.remove(collection_id)
                    cipher_collections.add(base_id)
                    self.change_collections_item(
                        cipher["Id"], list(cipher_collections)
                    )

                # delete the current collection
                self.delete_collection(organization_id, collection_id)

    # Collections users Management
    def add_collection_to_user(
        self,
        organization_id: str,
        user_org_id: str,
        accesses: dict,
        coll_id: str,
    ):
        return self.add_collections_to_user(
            organization_id, user_org_id, accesses, [coll_id]
        )

    def add_collections_to_user(
        self,
        organization_id: str,
        user_org_id: str,
        accesses: dict,
        coll_ids: List[str],
    ):
        data = {}
        coll_list = [
            {"HidePasswords": False, "Id": collection, "ReadOnly": False}
            for collection in coll_ids
        ]
        logger.debug("User info | %s", accesses)
        known_collection = next(
            (
                item
                for item in coll_list
                if item["Id"] not in accesses["Collections"]
            ),
            False,
        )
        if known_collection is False:
            return
        data["collections"] = accesses["Collections"]
        data["collections"].extend(coll_list)
        data["groups"] = accesses["Groups"]
        data["accessAll"] = accesses["AccessAll"]
        data["type"] = accesses["Type"]
        return self._api_request(
            "POST",
            f"api/organizations/{organization_id}/users/{user_org_id}",
            json=data,
        )

    def remove_collection_to_user(
        self,
        organization_id: str,
        user_org_id: str,
        accesses: dict,
        coll_id: str,
    ):
        return self.remove_collections_to_user(
            organization_id, user_org_id, accesses, [coll_id]
        )

    def remove_collections_to_user(
        self,
        organization_id: str,
        user_org_id: str,
        accesses: dict,
        coll_ids: List[str],
    ):
        data = {}
        known_collection = next(
            (
                item
                for item in accesses["Collections"]
                if item["Id"] in coll_ids
            ),
            False,
        )
        if known_collection is False:
            return
        data["collections"] = list(
            filter(lambda i: i["Id"] not in coll_ids, accesses["Collections"])
        )
        data["accessAll"] = accesses["AccessAll"]
        data["groups"] = accesses["Groups"]
        data["type"] = accesses["Type"]
        return self._api_request(
            "POST",
            f"api/organizations/{organization_id}/users/{user_org_id}",
            json=data,
        )

    # Ciphers Management
    def get_organization_items(self, organization_id, deleted=False):
        return (
            self._api_request(
                "GET",
                "api/ciphers/organization-details",
                params={"organizationId": organization_id, "deleted": deleted},
            )
            .json()
            .get("Data")
        )

    def get_organizations_collection_items(
        self, organization_id, collections_id
    ):
        ciphers = self.get_organization_items(organization_id)
        return list(
            filter(
                lambda cipher: (collections_id in cipher["CollectionIds"]),
                ciphers,
            )
        )

    def change_collections_item(self, item_id, collection_ids):
        self._api_request(
            "POST",
            f"api/ciphers/{item_id}/collections",
            json={"collectionIds": collection_ids},
        )

    # Collections Management
    def create_collection(
        self,
        org_id,
        collection_name,
        collections_names=None,
        collections_ids=None,
    ):
        if (
            collections_names is not None
            and collections_names.get(collection_name) is not None
        ):
            return collections_names[collection_name][-1]
        data = {
            "Name": encrypt(2, collection_name, self.get_org_key(org_id)),
            "groups": [],
            "users": [],
        }
        data = self._api_request(
            "POST", f"api/organizations/{org_id}/collections", json=data
        ).json()
        if data is not None and collections_names is not None:
            if collections_names.get(collection_name) is not None:
                collections_names[collection_name].append(data)
            else:
                collections_names[collection_name] = [data]
            collections_ids[data["Id"]] = data
        return data

    # Return 2 dicts: one indexed by name, one indexed by id,
    # both containing the collections details
    def get_organization_collections_dicts(self, org_id):
        resp = self._api_request(
            "GET", f"api/organizations/{org_id}/collections"
        )
        colls = resp.json().get("Data")
        res_by_name = {}
        res_by_id = {}
        org_key = self.get_org_key(org_id)
        for coll in colls:
            coll["Name"] = decrypt(coll["Name"], org_key).decode("utf-8")
            if res_by_name.get(coll["Name"]) is not None:
                res_by_name[coll["Name"]].append(coll)
            else:
                res_by_name[coll["Name"]] = [coll]
            res_by_id[coll["Id"]] = coll
        return res_by_name, res_by_id

    # Return a list of tuple (collection_name, collection_details)
    def get_organization_collections(self, org_id):
        resp = self._api_request(
            "GET", f"api/organizations/{org_id}/collections"
        )
        colls = resp.json().get("Data")
        res = []
        org_key = self.get_org_key(org_id)
        for coll in colls:
            coll["Name"] = decrypt(coll["Name"], org_key).decode("utf-8")
            res.append((coll["Name"], coll))
        return res

    def get_collection_id_or_create(
        self,
        org_id,
        collection_name,
        collections_names=None,
        collections_ids=None,
    ):
        if collections_names is None or collections_ids is None:
            (
                collections_names,
                collections_ids,
            ) = self.get_organization_collections_dicts(org_id)
        res = get_collection_id_from_ditcs(collections_names, collection_name)
        if res is None:
            new_coll = self.create_collection(
                org_id, collection_name, collections_names, collections_ids
            )
            if new_coll is not None:
                res = new_coll.get("Id")
        return res

    def delete_collection(self, organization_id, collection_id):
        return self._api_request(
            "DELETE",
            f"api/organizations/{organization_id}/collections/{collection_id}",
        )

    def get_matching_collections_ids_or_create(
        self,
        org_id,
        collection_name,
        collections_names=None,
        collections_ids=None,
    ):
        if collections_names is None or collections_ids is None:
            (
                collections_names,
                collections_ids,
            ) = self.get_organization_collections_dicts(org_id)
        res = get_matching_ids_from_ditcs(collections_names, collection_name)
        if not res:
            new_coll = self.create_collection(
                org_id, collection_name, collections_names, collections_ids
            )
            if new_coll is not None:
                res = [new_coll.get("Id")]
        return res

    def get_users_of_collection(self, organization_id, collection_id):
        users = self.get_users_of_collection_raw(
            organization_id, collection_id
        )
        return {u["Id"]: u for u in users}

    def get_users_of_collection_raw(self, organization_id, collection_id):
        users = self._api_request(
            "GET",
            f"api/organizations/{organization_id}/collections/{collection_id}/users",
            params={"includeCollections": True, "includeGroups": True},
        ).json()
        return users

    def set_users_of_collection(self, organization_id, collection_id, users):
        self._api_request(
            "PUT",
            f"api/organizations/{organization_id}/collections/{collection_id}/users",
            json=users,
        )

    def get_user_org_accesses(self, user_email, user_organization_ids):
        warn_not_maintain = False
        res = {}
        for org_id in user_organization_ids:
            org_users = {}
            try:
                org_users = self.get_organization_users(org_id)
            except HTTPError:
                warn_not_maintain = True
                continue
            org_user = org_users.get(user_email)
            user_org_id = org_user.get("Id")
            accesses = self.get_organization_user_details(org_id, user_org_id)
            res[org_id] = accesses
        return res, warn_not_maintain

    # Invitation
    def invite_organisation_collection(
        self, org_id, collection_id, email, access_type=2
    ):
        new_access = {
            "emails": [email],
            "Groups": [],
            "Collections": [
                {
                    "hidePasswords": False,
                    "id": collection_id,
                    "readOnly": False,
                }
            ],
            "accessAll": False,
            "type": access_type,
        }
        return self._api_request(
            "POST", f"api/organizations/{org_id}/users/invite", json=new_access
        )

    def invite_organisation_collections(
        self, org_id, collections_id, email, access_type=2
    ):
        new_access = {
            "emails": [email],
            "Groups": [],
            "Collections": [
                {
                    "hidePasswords": False,
                    "id": collection_id,
                    "readOnly": False,
                }
                for collection_id in collections_id
            ],
            "accessAll": False,
            "type": access_type,
        }
        return self._api_request(
            "POST", f"api/organizations/{org_id}/users/invite", json=new_access
        )

    def invite_organisation(self, org_id, user_accesses, email):
        data = {
            "emails": [email],
            "Groups": user_accesses["Groups"],
            "collections": user_accesses["Collections"],
            "accessAll": user_accesses["AccessAll"],
            "type": user_accesses["Type"],
        }
        return self._api_request(
            "POST", f"api/organizations/{org_id}/users/invite", json=data
        )

    # Re-invite a user with the same accesses. Return True if at least one
    # organization has been re-invited
    def invite_with_accesses(self, organizations, email):
        logger.info("Re-invite with accesses")
        for org_id, accesses in organizations.items():
            self.invite_organisation(org_id, accesses, email)
        return len(organizations) > 0
