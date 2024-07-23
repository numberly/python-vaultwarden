import unittest

from pydantic import TypeAdapter

from src.vaultwarden.models.sync import SyncData, VaultwardenUser
from vaultwarden.models.bitwarden import (
    Organization,
    ResplistBitwarden,
    OrganizationCollection,
)


class TestModelCases(unittest.TestCase):
    @staticmethod
    def read_json_payload(file_path):
        with open(file_path, "r") as file:
            return file.read()

    def test_organization(self):
        pascal_case_payload = self.read_json_payload(
            "tests/fixtures/test-organization/organization_pascal.json"
        )
        camel_case_payload = self.read_json_payload(
            "tests/fixtures/test-organization/organization_camel.json"
        )
        pascal = Organization.model_validate_json(pascal_case_payload)
        camel = Organization.model_validate_json(camel_case_payload)
        self.assertEqual(pascal.Name, camel.Name)

    def test_collections(self):
        pascal_case_payload = self.read_json_payload(
            "tests/fixtures/test-organization/collections/collections_pascal.json"
        )
        pascal_collections = (
            ResplistBitwarden[OrganizationCollection]
            .model_validate_json(pascal_case_payload)
            .Data
        )
        camel_case_payload = self.read_json_payload(
            "tests/fixtures/test-organization/collections/collections_camel.json"
        )
        camel_collections = (
            ResplistBitwarden[OrganizationCollection]
            .model_validate_json(camel_case_payload)
            .Data
        )
        self.assertEqual(len(pascal_collections), len(camel_collections))
        self.assertEqual(pascal_collections[0].Name, camel_collections[0].Name)
        self.assertEqual(pascal_collections[1].Name, camel_collections[1].Name)

    def test_sync_data(self):
        pascal_case_payload = self.read_json_payload(
            "tests/fixtures/test-account/sync_pascal.json"
        )
        camel_case_payload = self.read_json_payload(
            "tests/fixtures/test-account/sync_camel.json"
        )
        pascal = SyncData.model_validate_json(pascal_case_payload)
        camel = SyncData.model_validate_json(camel_case_payload)
        self.assertEqual(len(pascal.Ciphers), len(camel.Ciphers))
        self.assertEqual(len(pascal.Collections), len(camel.Collections))
        self.assertEqual(
            pascal.Collections[0].get("Name"), camel.Collections[0].get("name")
        )
        self.assertEqual(
            pascal.Collections[1].get("Name"), camel.Collections[1].get("name")
        )

    def test_admin_users(self):
        pascal_case_payload = self.read_json_payload(
            "tests/fixtures/admin/users_pascal.json"
        )
        camel_case_payload = self.read_json_payload(
            "tests/fixtures/admin/users_camel.json"
        )
        pascal = TypeAdapter(list[VaultwardenUser]).validate_json(
            pascal_case_payload
        )
        camel = TypeAdapter(list[VaultwardenUser]).validate_json(
            camel_case_payload
        )
        self.assertEqual(len(pascal), len(camel))
        self.assertEqual(pascal[0].Name, camel[0].Name)
        self.assertEqual(pascal[1].Name, camel[1].Name)
        self.assertEqual(pascal[0].Email, camel[0].Email)
        self.assertEqual(pascal[1].Email, camel[1].Email)
        self.assertEqual(pascal[0].UserEnabled, camel[0].UserEnabled)
        self.assertEqual(pascal[1].UserEnabled, camel[1].UserEnabled)


if __name__ == "__main__":
    unittest.main()
