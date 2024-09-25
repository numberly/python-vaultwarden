import unittest

from pydantic import TypeAdapter

from vaultwarden.models.bitwarden import (
    Organization,
    ResplistBitwarden,
    OrganizationUserDetails,
    CollectionUser,
)


class TestBitwardenModels(unittest.TestCase):
    @staticmethod
    def read_json_payload(file_path):
        with open(file_path, "r") as file:
            return file.read()

    def test_organization(self):
        payload = self.read_json_payload(
            "tests/fixtures/test-organization/organization_camel.json"
        )
        data = Organization.model_validate_json(payload)
        assert data.Name == "Test Organization"

    def test_organization_users(self):
        payload = self.read_json_payload(
            "tests/fixtures/test-organization/users_camel.json"
        )
        users = (
            ResplistBitwarden[OrganizationUserDetails]
            .model_validate_json(
                payload,
                context={"parent_id": "cda840d2-1de0-4f31-bd49-b30dacd7e8b0"},
            )
            .model_validate_json(payload)
        )
        assert len(users.Data) == 2
        assert users.Data[0].Email == "test-account@example.com"
        assert users.Data[1].Email == "test-account-2@example.com"

    def test_organization_collections(self):
        payload1 = self.read_json_payload(
            "tests/fixtures/test-organization/collections/test-collection/users_camel.json"
        )
        payload2 = self.read_json_payload(
            "tests/fixtures/test-organization/collections/test-collection-2/users_camel.json"
        )
        collection1 = TypeAdapter(list[CollectionUser]).validate_json(
            payload1,
            context={"parent_id": "9ed17918-31f6-4ac5-ac82-c11541cd8a7c"},
        )
        collection2 = TypeAdapter(list[CollectionUser]).validate_json(
            payload2,
            context={"parent_id": "3c73f14f-5a01-4016-98bb-9605146a1a49"},
        )

        assert len(collection1) == 0
        assert len(collection2) == 1


if __name__ == "__main__":
    unittest.main()
