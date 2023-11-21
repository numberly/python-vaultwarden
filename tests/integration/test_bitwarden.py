import os
import unittest

from vaultwarden.clients.bitwarden import BitwardenAPIClient
from vaultwarden.models.bitwarden import get_organization

# Get Bitwarden credentials from environment variables
url = os.environ.get("BITWARDEN_URL", None)
email = os.environ.get("BITWARDEN_EMAIL", None)
password = os.environ.get("BITWARDEN_PASSWORD", None)
client_id = os.environ.get("BITWARDEN_CLIENT_ID", None)
client_secret = os.environ.get("BITWARDEN_CLIENT_SECRET", None)
device_id = os.environ.get("BITWARDEN_DEVICE_ID", None)

bitwarden = BitwardenAPIClient(
    url, email, password, client_id, client_secret, device_id
)

# Get test organization id from environment variables
test_organization = os.environ.get("BITWARDEN_TEST_ORGANIZATION", None)


class BitwardenBasic(unittest.TestCase):
    def setUp(self) -> None:
        self.organization = get_organization(bitwarden, test_organization)
        self.test_colls_names = self.organization.collections(as_dict=True)
        self.test_colls_ids = self.organization.collections()
        self.test_users = self.organization.users()
        self.test_org_ciphers = self.organization.ciphers()
        self.test_coll_1_cipher = self.organization.ciphers(
            self.test_colls_names.get("1_cipher").Id
        )
        self.test_coll_2_ciphers = self.organization.ciphers(
            self.test_colls_names.get("2_ciphers").Id
        )
        self.test_coll_1_user = self.test_colls_names.get("1_user").users()
        self.test_coll_2_users = self.test_colls_names.get("2_users").users()

    def test_get_organization_users(self):
        self.assertEqual(len(self.test_users), 4)

    def test_get_organization_items(self):
        self.assertEqual(len(self.test_org_ciphers), 5)

    def test_get_organization_collection_1_item(self):
        self.assertEqual(len(self.test_coll_1_cipher), 1)

    def test_get_organization_collection_2_items(self):
        self.assertEqual(len(self.test_coll_2_ciphers), 2)

    def test_get_organizations_collections(self):
        self.assertEqual(len(self.test_colls_ids), 5)

    def test_get_users_of_collection_1(self):
        self.assertEqual(len(self.test_coll_1_user), 1)

    def test_get_users_of_collection_2(self):
        self.assertEqual(len(self.test_coll_2_users), 2)

    def test_create_delete_collection(self):
        len_old_colls = len(self.organization.collections(force_refresh=True))
        new_coll = self.organization.create_collection("create_delete_test")
        new_colls = self.organization.collections(force_refresh=True)
        self.assertEqual(len(new_colls), len_old_colls + 1)
        self.organization.delete_collection(new_coll.Id)
        new_colls = self.organization.collections(force_refresh=True)
        self.assertEqual(len(new_colls), len_old_colls)

    def test_set_users_of_collection(self):
        coll = self.test_colls_names.get("1_user")
        coll.set_users(self.test_coll_2_users)
        users = coll.users()
        self.assertEqual(len(users), 2)
        coll.set_users(self.test_coll_1_user)
        users = coll.users()
        self.assertEqual(len(users), 1)

    def test_add_remove_collection_from_user(self):
        user_org_id = self.test_coll_1_user[0].UserId
        user_infos = self.organization.user(user_org_id)
        coll_1_user = self.test_colls_names.get("1_user")
        user_infos.remove_collections([coll_1_user.Id])
        self.assertEqual(
            len(coll_1_user.users()),
            0,
        )
        user_infos.add_collections([coll_1_user.Id])
        users = coll_1_user.users()
        self.assertEqual(
            len(users),
            1,
        )

    def test_deduplicate(self):
        # Todo build test fixtures and delete them at the end of the test
        return


if __name__ == "__main__":
    unittest.main()
