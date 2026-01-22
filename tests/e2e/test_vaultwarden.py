# Unit test for VaultwardenAdminClient
import os
import unittest

from vaultwarden.clients.vaultwarden import VaultwardenAdminClient

from .docker_helper import start_docker, stop_docker

# Get Vaultwarden Admin credentials from environment variables
url = os.environ.get("VAULTWARDEN_URL", None)
admin_token = os.environ.get("VAULTWARDEN_ADMIN_TOKEN", None)


# TODO Add tests for VaultwardenAdminClient
class VaultwardenAdminClientBasic(unittest.TestCase):
    def tearDownClass() -> None:
        stop_docker()

    def setUp(self) -> None:
        start_docker()
        self.vaultwarden = VaultwardenAdminClient(
            url=url, admin_secret_token=admin_token
        )

    def tearDown(self) -> None:
        stop_docker()
