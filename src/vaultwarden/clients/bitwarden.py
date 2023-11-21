from typing import Literal
from uuid import UUID

from bitwardentools import caseinsentive_key_search
from bitwardentools.crypto import make_master_key
from httpx import Client, Response

from vaultwarden.models.api_models import ApiToken
from vaultwarden.models.bitwarden import Organization
from vaultwarden.models.exception_models import BitwardenError
from vaultwarden.utils.tools import log_raise_for_status


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
        self._api_token: ApiToken | None = None
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

    def api_request(
        self,
        method: Literal["GET", "POST", "DELETE", "PUT"],
        path: str,
        **kwargs: any,
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

    def _api_request(
        self,
        method: Literal["GET", "POST", "DELETE", "PUT"],
        path: str,
        **kwargs: any,
    ) -> Response:
        return self.api_request(method, path, **kwargs)

    def get_sync(self):
        if self.sync is None:
            resp = self._api_request("GET", "api/sync")
            self.sync = resp.json()
        return self.sync

    def organization(self, organization_id: UUID | str) -> Organization:
        resp = self._api_request("GET", f"api/organizations/{organization_id}")
        return Organization.model_validate_json(
            resp.text, context={"client": self, "parent_id": organization_id}
        )
