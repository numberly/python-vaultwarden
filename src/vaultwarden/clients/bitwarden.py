from typing import Literal
from uuid import UUID

from httpx import Client, Response

from vaultwarden.models.exception_models import BitwardenError
from vaultwarden.models.sync import ConnectToken, SyncData
from vaultwarden.utils.crypto import make_master_key
from vaultwarden.utils.logger import log_raise_for_status


class BitwardenAPIClient:
    def __init__(
        self,
        url: str,
        email: str,
        password: str,
        client_id: str,
        client_secret: str,
        device_id: UUID | str,
        timeout: int = 30,
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
            timeout=timeout,
        )
        self._connect_token: ConnectToken | None = None
        self._sync: SyncData | None = None

    @property
    def connect_token(self) -> ConnectToken | None:
        return self._connect_token

    @connect_token.setter
    def connect_token(self, value: ConnectToken):
        self._connect_token = value

    # refresh connect token if expired
    def _refresh_connect_token(self):
        if (
            self.connect_token is None
            or self.connect_token.refresh_token is None
        ):
            self._set_connect_token()
            return
        headers = {
            "content-type": "application/x-www-form-urlencoded; charset=utf-8",
        }
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": self.connect_token.refresh_token,
        }
        resp = self._http_client.post(
            "identity/connect/token", headers=headers, data=payload
        )
        self._connect_token = ConnectToken.model_validate_json(resp.text)

    def _set_connect_token(self):
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
        self._connect_token = ConnectToken.model_validate_json(resp.text)
        self._connect_token.master_key = make_master_key(
            password=self.password,
            salt=self.email,
            iterations=self._connect_token.KdfIterations,
        )

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
            "content-type": "application/json; charset=utf-8",
            "Accept": "*/*",
        }
        return self._http_client.request(
            method, path, headers=headers, **kwargs
        )

    def sync(self, force_refresh: bool = False) -> SyncData:
        if self._sync is None or force_refresh:
            resp = self._api_request("GET", "api/sync")
            self._sync = SyncData.model_validate_json(resp.text)
        return self._sync
