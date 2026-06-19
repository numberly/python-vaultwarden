import typing
from typing import Literal
from uuid import UUID

from httpx import Client, Response

from vaultwarden.models.bitwarden import (
    CipherDetail,
    CipherDetails,
    Organization,
    OrganizationCollection,
    OrgData,
    RegisterData,
)
from vaultwarden.models.crypto import CryptoContext
from vaultwarden.models.exception_models import BitwardenError
from vaultwarden.models.sync import ConnectToken, SyncData
from vaultwarden.utils.crypto import masterPasswordHash
from vaultwarden.utils.logger import log_raise_for_status

if typing.TYPE_CHECKING:
    from vaultwarden.models.bitwarden import (
        Kdf,
    )


class BitwardenAPIClient:
    def __init__(
        self,
        url: str,
        email: str | None,
        password: str,
        client_id: str,
        client_secret: str,
        device_id: UUID | str,
        timeout: int = 30,
    ):
        # if one of the parameters is None, raise an exception
        if not all([url, password, client_id, client_secret, device_id]):
            raise BitwardenError("All parameters are required")
        self.email: str | None = email
        self.password = password
        self.client_id = client_id
        self.client_secret = client_secret
        self.device_id = device_id
        self.url = url.strip("/")
        self._http_client = Client(
            base_url=f"{self.url}/",
            event_hooks={"response": [log_raise_for_status]},
            headers={"Bitwarden-Client-Version": "2024.1.0"},
            timeout=timeout,
        )
        self._connect_token: ConnectToken | None = None
        self._sync: SyncData | None = None

    def close(self):
        self._http_client.close()

    @property
    def connect_token(self) -> ConnectToken | None:
        return self._connect_token

    @connect_token.setter
    def connect_token(self, value: ConnectToken):
        self._connect_token = value

    @property
    def masterPasswordHash(self):  # noqa: N802
        return masterPasswordHash(
            self._connect_token._master_key, self.password
        )

    # refresh connect token if expired
    def _refresh_connect_token(self):
        if (
            self.connect_token is None
            or self.connect_token.refresh_token is None
        ):
            self._set_connect_token()
        else:
            payload = {
                "grant_type": "refresh_token",
                "refresh_token": self.connect_token.refresh_token,
            }
            self._set_connect_token(payload)

    def _set_connect_token(self, refresh: dict | None = None):
        payload = refresh or {
            "grant_type": "client_credentials",
            "client_secret": f"{self.client_secret}",
            "client_id": f"{self.client_id}",
            "scope": "api",
            # 21 for "SDK", see https://github.com/bitwarden/server/blob/master/src/Core/Enums/DeviceType.cs
            "deviceType": 21,
            "deviceIdentifier": f"{self.device_id}",
            "deviceName": "python-vaultwarden",
        }
        headers = {
            "content-type": "application/x-www-form-urlencoded; charset=utf-8",
        }
        resp = self._http_client.post(
            "identity/connect/token", headers=headers, data=payload
        )
        if self.email is None:
            access_token = resp.json()["access_token"]
            headers = {
                "Authorization": f"Bearer {access_token}",
                "content-type": "application/json; charset=utf-8",
                "Accept": "*/*",
            }
            mresp = self._http_client.get(
                "api/accounts/profile", headers=headers
            )
            self.email = mresp.json()["email"]

        self._connect_token = ConnectToken.model_validate_json(
            resp.text, context=CryptoContext(client=self)
        )

        return

    # login to api
    def _api_login(self) -> None:
        if self.connect_token is not None:
            if self.connect_token.is_expired():
                self._refresh_connect_token()
            return

        self._set_connect_token()

    def api_request(
        self,
        method: Literal["GET", "POST", "DELETE", "PUT"],
        path: str,
        **kwargs,
    ) -> Response:
        return self._api_request(method, path, **kwargs)

    def _api_request(
        self,
        method: Literal["GET", "POST", "DELETE", "PUT"],
        path: str,
        **kwargs,
    ) -> Response:
        self._api_login()
        if self.connect_token is None:
            raise BitwardenError("Fail to connect")
        headers = {
            "Authorization": f"Bearer {self.connect_token.access_token}",
            "Accept": "*/*",
        }

        if kwargs.get("json") is not None:
            headers["content-type"] = "application/json; charset=utf-8"

        return self._http_client.request(
            method, path, headers=headers, **kwargs
        )

    def sync(self, force_refresh: bool = False) -> SyncData:
        if self._sync is None or force_refresh:
            resp = self._api_request("GET", "api/sync")
            return self._sync_step(resp.json())
        return self._sync

    def _sync_step(self, data: dict) -> SyncData:
        v: dict[str, typing.Any] = {
            "profile": data.get("profile") or data.get("Profile"),
            "ciphers": [],
            "collections": [],
            "folders": [],
            "policies": [],
            "sends": [],
            "domains": {},
        }
        # populate self._sync.Profile
        self._sync = SyncData.model_validate(
            v, context=CryptoContext(client=self)
        )
        # uses self._sync.Profile
        self._sync = SyncData.model_validate(
            data,
            context=CryptoContext(client=self),
        )
        return self._sync

    def create_organization(
        self,
        name: str,
        email: str,
        default_collection_name: str = "DefaultCollection",
    ) -> Organization:
        if not self.connect_token:
            raise BitwardenError("Not connected")
        assert self._connect_token

        from secrets import token_bytes

        req = OrgData.model_construct(
            Name=name,
            BillingEmail=email,
            CollectionName=default_collection_name,
            PlanType=0,
            Key=token_bytes(64),
        )
        ctx = CryptoContext(client=self)
        ctx.push(self._connect_token.PrivateKey)
        data = req.model_dump(
            by_alias=True, exclude_none=True, exclude_unset=True, context=ctx
        )
        v = self.api_request("POST", "api/organizations", json=data)
        return Organization.model_validate(
            v.json(), context=CryptoContext(client=self)
        )

    #    def get_organization(self, name) -> "Organization":
    #        pass

    def create_user(
        self,
        email: str,
        password: str,
        name,
        kdf: "Kdf",
    ):
        assert email == email.lower(), "email is not lowercase"
        assert len(password) >= 8, "password is too short (< 8 characters)"

        rd = RegisterData.model_construct(
            email=email,
            password=password,
            name=name,
            **kdf.model_dump(by_alias=True),
        )
        data = rd.model_dump(
            by_alias=True,
            exclude_none=True,
            exclude_unset=True,
            context=CryptoContext(client=self),
        )
        resp = self._api_request("POST", "api/accounts/register", json=data)
        #        user = self._api_request("GET", f"api/users/{email}")
        return resp

    def search_items(
        self,
        uri: str | None = None,
        name: str | None = None,
        organisations: list[Organization] | None = None,
        collections: list[OrganizationCollection] | None = None,
        types: list[type[CipherDetails]] | None = None,
    ) -> typing.Generator["CipherDetails", None, None]:
        selectors: list[typing.Callable[["CipherDetails"], bool]] = list()

        if uri is not None:

            def by_uri(item: CipherDetails) -> bool:
                return item.uri_match(uri)

            selectors.append(by_uri)

        if name is not None:

            def by_name(item: CipherDetails) -> bool:
                return name in item.Name

            selectors.append(by_name)

        if organisations is not None:

            def by_organisation(item: CipherDetails) -> bool:
                return item.OrganizationId in [o.Id for o in organisations]

            selectors.append(by_organisation)

        if collections is not None:

            def by_collection(item: CipherDetails) -> bool:
                return (
                    len(
                        set(item.CollectionIds)
                        & set([o.Id for o in collections])
                    )
                    > 0
                )

            selectors.append(by_collection)

        if types is not None:

            def by_type(item: CipherDetails) -> bool:
                return isinstance(item, tuple(types))

            selectors.append(by_type)

        def select_func(item: CipherDetails) -> bool:
            return all([selector(item) for selector in selectors])

        return self.select_items(select_func)

    def select_items(
        self, select_func: typing.Callable[["CipherDetails"], bool]
    ) -> typing.Generator["CipherDetails", None, None]:
        assert self._sync
        for i in self._sync.Ciphers:
            if select_func(i):
                yield i

    def create_item(
        self,
        item: "CipherDetails",
        organization: typing.Optional["Organization"],
        collections: list["OrganizationCollection"] | None,
    ) -> "CipherDetails":
        if organization:
            assert organization and (
                collections is not None and len(collections)
            ), (organization, collections)
            path = "api/ciphers/admin"
            key = organization.key()
            item.OrganizationId = organization.Id
            data = {
                "type": item.Type,
                "cipher": item.model_dump(
                    by_alias=True,
                    mode="json",
                    context=CryptoContext(client=self, stack=[key]),
                ),
                "collectionIds": [str(i.Id) for i in collections],
            }
        else:
            path = "api/ciphers"
            assert self.connect_token is not None
            key = self.connect_token.Key
            data = item.model_dump(
                by_alias=True,
                mode="json",
                context=CryptoContext(client=self, stack=[key]),
            )

        resp = self._api_request("POST", path, json=data)
        return CipherDetail.validate_json(
            resp.text, context=CryptoContext(client=self)
        )
