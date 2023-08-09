import os
import unittest

from vaultwarden.clients.bitwarden import BitwardenClient

# Get Bitwarden credentials from environment variables
url = os.environ.get('BITWARDEN_URL', None)
email = os.environ.get('BITWARDEN_EMAIL', None)
password = os.environ.get('BITWARDEN_PASSWORD', None)
client_id = os.environ.get('BITWARDEN_CLIENT_ID', None)
client_secret = os.environ.get('BITWARDEN_CLIENT_SECRET', None)
device_id = os.environ.get('BITWARDEN_DEVICE_ID', None)

bitwarden = BitwardenClient(url, email, password, client_id, client_secret, device_id)

# Get test organization id from environment variables
test_organization = os.environ.get('BITWARDEN_TEST_ORGANIZATION', None)


class BitwardenBasic(unittest.TestCase):
    def setUp(self) -> None:
        self.test_colls_names, self.test_colls_ids = bitwarden.get_organization_collections_dicts(
            test_organization)
        self.test_users = bitwarden.get_organization_users(test_organization)
        self.test_org_ciphers = bitwarden.get_organization_items(test_organization)
        self.test_coll_1_cipher = bitwarden.get_organizations_collection_items(test_organization,
                                                                               self.test_colls_names.get("1_cipher")[
                                                                                   0].get("Id"))
        self.test_coll_2_ciphers = bitwarden.get_organizations_collection_items(test_organization,
                                                                                self.test_colls_names.get(
                                                                                    "2_ciphers")[
                                                                                    0].get("Id"))
        self.test_coll_1_user = bitwarden.get_users_of_collection_raw(test_organization,
                                                                      self.test_colls_names.get(
                                                                          "1_user")[
                                                                          0].get("Id"))
        self.test_coll_2_users = bitwarden.get_users_of_collection_raw(test_organization,
                                                                       self.test_colls_names.get(
                                                                           "2_users")[
                                                                           0].get("Id"))

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

    def test_get_no_2fa_users(self):
        part1, part2 = bitwarden.get_no_2fa_users()
        self.assertGreaterEqual(len(part1 + part2), 1)

    def test_create_delete_collection(self):
        _, old_colls_ids = bitwarden.get_organization_collections_dicts(test_organization)
        new_coll = bitwarden.create_collection(test_organization, "create_delete_test")
        _, colls_ids = bitwarden.get_organization_collections_dicts(test_organization)
        self.assertEqual(len(colls_ids), len(old_colls_ids) + 1)
        bitwarden.delete_collection(test_organization, new_coll["Id"])
        _, colls_ids = bitwarden.get_organization_collections_dicts(test_organization)
        self.assertEqual(len(colls_ids), len(old_colls_ids))

    def test_set_users_of_collection(self):
        bitwarden.set_users_of_collection(test_organization, self.test_colls_names.get("1_user")[0].get("Id"),
                                          self.test_coll_2_users)
        self.assertEqual(
            len(bitwarden.get_users_of_collection_raw(test_organization,
                                                      self.test_colls_names.get("1_user")[0].get("Id"))),
            2
        )
        bitwarden.set_users_of_collection(test_organization, self.test_colls_names.get("1_user")[0].get("Id"),
                                          self.test_coll_1_user)
        self.assertEqual(
            len(bitwarden.get_users_of_collection_raw(test_organization,
                                                      self.test_colls_names.get("1_user")[0].get("Id"))),
            1
        )

    def test_add_remove_collection_from_user(self):
        user_org_id = self.test_coll_1_user[0].get("Id")
        user_infos = bitwarden.get_organization_user_details(test_organization, user_org_id)
        bitwarden.remove_collections_to_user(test_organization, user_org_id, user_infos,
                                             [self.test_colls_names.get("1_user")[0].get("Id")])
        self.assertEqual(len(bitwarden.get_users_of_collection_raw(test_organization,
                                                                   self.test_colls_names.get(
                                                                       "1_user")[
                                                                       0].get("Id"))), 0)
        user_infos = bitwarden.get_organization_user_details(test_organization, user_org_id)
        bitwarden.add_collection_to_user(test_organization, self.test_colls_names.get("1_user")[0].get("Id"),
                                         user_org_id, user_infos)
        self.assertEqual(len(bitwarden.get_users_of_collection_raw(test_organization,
                                                                   self.test_colls_names.get(
                                                                       "1_user")[
                                                                       0].get("Id"))), 1)

    def test_deduplicate(self):
        # Todo build test fixtures and delete them at the end of the test
        return


if __name__ == '__main__':
    unittest.main()
