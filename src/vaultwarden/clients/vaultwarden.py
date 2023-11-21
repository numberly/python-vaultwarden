import http
from http.cookiejar import Cookie
from typing import Any, Literal, Optional
from uuid import UUID

from httpx import Client, HTTPStatusError, Response
from pydantic import TypeAdapter

from vaultwarden.clients.bitwarden import BitwardenAPIClient
from vaultwarden.models.bitwarden import get_organization
from vaultwarden.models.enum import VaultwardenUserStatus
from vaultwarden.models.exception_models import VaultwardenAdminError
from vaultwarden.models.sync import VaultwardenUser
from vaultwarden.utils.logger import log_raise_for_status, logger


class VaultwardenAdminClient:
    _users: list[VaultwardenUser]
    _users_index: dict[UUID, int]
    _users_alias: dict[str, UUID]

    def __init__(
        self,
        url: str,
        admin_secret_token: str,
        preload_users: bool,
        timeout: int = 30,
    ):
        # If url or admin_secret_token is None, raise an exception
        if not url or not admin_secret_token:
            raise VaultwardenAdminError("Missing url or admin_secret_token")
        self.admin_secret_token = admin_secret_token
        self.url = url.strip("/")
        self._http_client = Client(
            base_url=f"{self.url}/admin/",
            event_hooks={"response": [log_raise_for_status]},
            timeout=timeout,
        )
        self._users_index = {}
        self._users_alias = {}
        self._users = []
        # Preload all users infos
        if preload_users:
            self._load_users()

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

    def _load_users(self) -> None:
        resp = self._admin_request("GET", "users")
        self._users = TypeAdapter(list[VaultwardenUser]).validate_json(
            resp.text
        )
        self._users_index = {u.Id: i for i, u in enumerate(self._users)}
        self._users_alias = {u.Email: u.Id for u in self._users}

    def user(
        self, email=None, uuid=None, force_refresh=False
    ) -> VaultwardenUser:
        if email is None and uuid is None:
            raise VaultwardenAdminError("Missing email or id")
        if email is not None and uuid is not None:
            raise VaultwardenAdminError("Both email and id given")
        if force_refresh or not self._users:
            self._load_users()
        res_uuid = uuid
        if email is not None:
            res_uuid = self._users_alias.get(email)
        if res_uuid is None:
            raise VaultwardenAdminError(f"User '{email}' not found")
        index = self._users_index.get(res_uuid)
        if index is None:
            raise VaultwardenAdminError(f"User '{res_uuid}' not found")
        return self._users[index]

    def get_user(
        self, email=None, uuid=None, force_refresh=False
    ) -> VaultwardenUser | None:
        try:
            return self.user(
                email=email, uuid=uuid, force_refresh=force_refresh
            )
        except VaultwardenAdminError:
            return None

    def users(
        self,
        as_email_dict=False,
        as_uuid_dict=False,
        force_refresh=False,
        mfa: bool | None = None,
        enabled: bool | None = None,
        exclude_invited: bool = False,
    ) -> (
        list[VaultwardenUser]
        | dict[str, VaultwardenUser]
        | dict[UUID, VaultwardenUser]
    ):
        if force_refresh or not self._users:
            self._load_users()
        res = self._users
        if mfa is not None:
            res = [u for u in self._users if u.TwoFactorEnabled == mfa]
        if enabled is not None:
            res = [u for u in res if u.UserEnabled == enabled]
        if exclude_invited:
            res = [u for u in res if u.status != VaultwardenUserStatus.Invited]
        if as_email_dict:
            return {u.Email: u for u in res}
        if as_uuid_dict:
            return {u.Id: u for u in res}
        return res

    # User Management Part
    def invite(self, email: str) -> bool:
        res = True
        try:
            self._admin_request("POST", "invite", json={"email": email})
        except HTTPStatusError as e:
            res = e.response.status_code == http.HTTPStatus.CONFLICT
        if not res:
            logger.warning(f"Failed to invite {email}")
        else:
            self._load_users()
        return res

    def delete(self, identifier: str) -> bool:
        logger.info(f"Deleting {identifier} account")
        res = True
        try:
            self._admin_request("POST", f"users/{identifier}/delete")
        except HTTPStatusError:
            res = False
        if not res:
            logger.warning(f"Failed to delete {identifier}")
        else:
            self._load_users()
        return res

    def set_user_enabled(self, identifier: str | UUID, enabled: bool) -> None:
        """Disabling a user also deauthorizes all its sessions"""
        if enabled:
            resp = self._admin_request("POST", f"users/{identifier}/enable")
        else:
            resp = self._admin_request("POST", f"users/{identifier}/disable")
        resp.raise_for_status()

    def remove_2fa(self, uuid=None, email=None) -> bool:
        user = self.get_user(uuid=uuid, email=email)
        if user is None:
            logger.warning(f"User '{uuid}' not found")
            return False
        if not user.TwoFactorEnabled:
            logger.warning(f"User '{uuid}' has no 2FA enabled")
            return False
        try:
            self._admin_request("POST", f"users/{uuid}/remove-2fa")
        except HTTPStatusError:
            logger.warning(f"Failed to remove 2FA for {uuid}")
            return False
        return True

    def reset_account(
        self, email: str, admin_bitwarden_client: BitwardenAPIClient
    ):
        user: VaultwardenUser = self.user(email=email)
        warning = False
        orgs = []
        for profile_org in user.Organizations:
            try:
                orgs.append(
                    get_organization(admin_bitwarden_client, profile_org.Id)
                )
            except HTTPStatusError:
                logger.warning(
                    f"Given Bitwarden client has no access to org"
                    f" '{profile_org.Name}' ({profile_org.Id})"
                )
                warning = True
        if warning:
            check = input(
                "WARNING: A organisation where you where present is not "
                "maintain by SOC account\n"
                "Type 'yes' if you still want to reset the account"
            )
            if check != "yes":
                logger.warning(f"'{check}' != of 'yes' - Cancelling the reset")
                return
            logger.warning(
                f"Doing reset on {email} despite having not complete "
                f"information on its accesses"
            )
        self.delete(str(user.Id))
        for org in orgs:
            users_org = org.users(search=email)
            if len(users_org) > 0:
                user_details = users_org[0]
                org.invite(
                    email,
                    collections=user_details.Collections,
                    access_all=user_details.AccessAll,
                    user_type=user_details.Type,
                )
        if len(orgs) == 0:
            logger.warning("No organisation in the rights")
            self.invite(email)
        return None

    def transfer_account_rights(
        self,
        previous_email: str,
        new_email: str,
        admin_bitwarden_client: BitwardenAPIClient,
    ):
        user: VaultwardenUser = self.user(email=previous_email)
        orgs = []
        for profile_org in user.Organizations:
            try:
                orgs.append(
                    get_organization(admin_bitwarden_client, profile_org.Id)
                )
            except Exception:
                logger.warning(
                    f"Given Bitwarden client has no access to org "
                    f"'{profile_org.Name}' ({profile_org.Id})"
                )
        if len(orgs) == 0:
            logger.warning("No organisation in the rights")
            self.invite(new_email)
        for org in orgs:
            users_org = org.users(search=previous_email)
            if len(users_org) > 0:
                user_details = users_org[0]
                org.invite(
                    new_email,
                    collections=user_details.Collections,
                    access_all=user_details.AccessAll,
                    user_type=user_details.Type,
                )
        self.set_user_enabled(str(user.Id), enabled=False)
