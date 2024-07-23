import unittest

from pydantic import TypeAdapter

from vaultwarden.models.sync import VaultwardenUser


class TestVaultwardenModels(unittest.TestCase):
    @staticmethod
    def read_json_payload(file_path):
        with open(file_path, "r") as file:
            return file.read()

    def test_users(self):
        payload = self.read_json_payload(
            "tests/fixtures/admin/users_camel.json"
        )
        data = TypeAdapter(list[VaultwardenUser]).validate_json(payload)
        assert len(data) == 2
        assert data[0].Email == "test-account@example.com"
        assert data[1].Email == "test-account-2@example.com"
        assert data[0].Name == "Test Account"
        assert data[1].Name == "Test Account 2"
        assert data[0].UserEnabled
        assert data[1].UserEnabled


if __name__ == "__main__":
    unittest.main()
