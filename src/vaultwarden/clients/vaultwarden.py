import http
from http.cookiejar import Cookie
from typing import Any, Literal, Optional

from httpx import Client, HTTPStatusError, Response

from vaultwarden.clients.bitwarden import BitwardenClient
from vaultwarden.models.api_models import VaultWardenUser
from vaultwarden.models.exception_models import VaultwardenAdminError
from vaultwarden.utils.logger import logger
from vaultwarden.utils.tools import log_raise_for_status


class VaultwardenAdminClient:
    def __init__(self, url: str, admin_secret_token: str, preload_users: bool):
        # If url or admin_secret_token is None, raise an exception
        if not url or not admin_secret_token:
            raise VaultwardenAdminError("Missing url or admin_secret_token")
        self.admin_secret_token = admin_secret_token
        self.url = url.strip("/")
        self._http_client = Client(
            base_url=f"{self.url}/admin/",
            event_hooks={"response": [log_raise_for_status]},
        )
        self._id_mail_pool: dict[str, str] = {}
        # Preload all users infos
        if preload_users:
            _ = self.get_all_users()

    def _get_admin_cookie(self) -> Optional[Cookie]:
        """Get the session cookie, required to authenticate requests"""
        bw_cookies = (
            c for c in self._http_client.cookies.jar if c.name == "VW_ADMIN"
        )
        return next(bw_cookies, None)

    def _admin_login(self) -> None:
        cookie = self._get_admin_cookie()

        if cookie and not cookie.is_expired():
            # Cookie is valid, nothing to do
            return

        # Refresh
        self._http_client.post("", data={"token": self.admin_secret_token})

    def _admin_request(
        self, method: Literal["GET", "POST"], path: str, **kwargs: Any
    ) -> Response:
        self._admin_login()
        return self._http_client.request(method, path, **kwargs)

    def _fill_id_mail_pool(self, users: list[VaultWardenUser]) -> None:
        """Cache the email->GUID mapping for the given users

        Necessary since Vaultwarden does not offer a search or
        query-by-email endpoint
        """
        self._id_mail_pool |= {u["Email"]: u["Id"] for u in users}

    # User Management Part
    def invite(self, email: str) -> Optional[VaultWardenUser]:
        try:
            resp = self._admin_request("POST", "invite", json={"email": email})
        except HTTPStatusError as e:
            # User already exists
            if e.response.status_code == http.HTTPStatus.CONFLICT:
                return None
            raise
        return resp.json()

    def delete(self, identifier: str) -> None:
        logger.info(f"Deleting {identifier} account")
        resp = self._admin_request("POST", f"users/{identifier}/delete")
        resp.raise_for_status()

    def set_user_enabled(self, identifier: str, enabled: bool) -> None:
        """Disabling a user also deauthorizes all its sessions"""
        if enabled:
            resp = self._admin_request("POST", f"users/{identifier}/enable")
        else:
            resp = self._admin_request("POST", f"users/{identifier}/disable")
        resp.raise_for_status()

    def remove_2fa(self, email: str) -> None:
        user = self.get_user(email)
        if user is None:
            raise VaultwardenAdminError(f"User {email} not found")
        self._admin_request(
            "POST", f"users/{email}/remove-2fa"
        ).raise_for_status()

    def get_user(self, search: str) -> VaultWardenUser:
        """Search term is either an email in cache or a UUID.
        For textual search, use get_all_resources (expensive)"""

        assert isinstance(search, str)

        if not self._id_mail_pool:
            self.get_all_users()

        if search in self._id_mail_pool:
            search = self._id_mail_pool[search]
        elif "@" in search:
            # search is not UUID (probably an email) but wasn't found in cache
            raise VaultwardenAdminError(f"User {search} not found")
        # else assume it's a UUID
        resp = self._admin_request("GET", f"users/{search}")
        resp.raise_for_status()

        return resp.json()

    def get_all_users(self) -> list[VaultWardenUser]:
        users: list[VaultWardenUser] = self._admin_request(
            "GET", "users"
        ).json()
        self._fill_id_mail_pool(users)
        return users

    def reset_account(self, email: str, bitwarden_client: BitwardenClient):
        user: VaultWardenUser = self.get_user(email)
        accesses, warning = bitwarden_client.get_user_org_accesses(
            user_email=email, user_organization_ids=user.get("Organizations")
        )
        if warning:
            check = input(
                "WARNING: A organisation where you where present is not "
                "maintain by SOC account\n"
                "Press 'yes' if you still want to reset the account"
            )
            if check != "yes":
                logger.warning("Cancelling the reset")
                return
            logger.warning(
                f"Doing reset on {email} despite having not complete "
                f"information on its accesses"
            )
        self.delete(user["Id"])
        bitwarden_client.invite_with_accesses(accesses, user.get("Email"))
        return None

    def transfer_account_rights(
        self,
        previous_email: str,
        new_email: str,
        bitwarden_client: BitwardenClient,
    ):
        res = True
        user: VaultWardenUser = self.get_user(previous_email)
        accesses, warning = bitwarden_client.get_user_org_accesses(
            user_email=previous_email,
            user_organization_ids=user.get("Organizations"),
        )
        if warning:
            logger.warning(
                "A organisation in the rights is not maintain by SOC account"
            )
        if len(accesses) == 0:
            logger.warning("No organisation in the rights")
            res = self.invite(new_email) is not None
        else:
            res = bitwarden_client.invite_with_accesses(accesses, new_email)
        if res:
            self.set_user_enabled(user["Id"], enabled=False)
        return res
