import unittest

from vaultwarden.models.sync import SyncData


class TestSyncModels(unittest.TestCase):
    @staticmethod
    def read_json_payload(file_path):
        with open(file_path, "r") as file:
            return file.read()

    def test_syncdata(self):
        payload = self.read_json_payload(
            "tests/fixtures/test-account/sync_camel.json"
        )
        data = SyncData.model_validate_json(payload)
        assert len(data.Ciphers) == 2
        assert len(data.Collections) == 3
        assert len(data.Profile.Organizations) == 1
        assert data.Profile.Organizations[0].Name == "Test Organization"
        assert len(data.Ciphers) == 2
        assert data.Profile.Email == "test-account@example.com"


if __name__ == "__main__":
    unittest.main()
