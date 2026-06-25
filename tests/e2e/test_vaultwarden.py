# Unit test for VaultwardenAdminClient
import os
import unittest

from vaultwarden.clients.vaultwarden import VaultwardenAdminClient

from . import env_from_ci

env_from_ci()

# Get Vaultwarden Admin credentials from environment variables
url = os.environ.get("VAULTWARDEN_URL", None)
admin_token = os.environ.get("VAULTWARDEN_ADMIN_TOKEN", None)


class VaultwardenAdminClientBasic(unittest.TestCase):
    def setUp(self) -> None:
        self.vaultwarden = VaultwardenAdminClient(
            url=url, admin_secret_token=admin_token, preload_users=False
        )

    def test_users(self):
        self.vaultwarden.users()
