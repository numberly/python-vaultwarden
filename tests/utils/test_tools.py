import unittest

from vaultwarden.utils.tools import (
    get_collection_id_from_ditcs,
    get_matching_ids_from_ditcs,
)


# Unit tests for vaultwarden/utils/tools.py
class TestTools(unittest.TestCase):
    def setUp(self) -> None:
        self.collections_names = {
            "test": [{"Id": "test"}],
            "test/test": [{"Id": "test/test"}],
            "test/test/test": [{"Id": "test/test/test"}],
            "test2": [{"Id": "test1"}, {"Id": "test2"}],
            "test2/test2": [{"Id": "test2/test2"}],
        }

    def test_get_collection_id_from_ditcs(self):
        self.assertEqual(
            get_collection_id_from_ditcs(self.collections_names, "test"), "test"
        )
        self.assertEqual(
            get_collection_id_from_ditcs(self.collections_names, "test/test"),
            "test/test",
        )
        self.assertEqual(
            get_collection_id_from_ditcs(self.collections_names, "test/test/test"),
            "test/test/test",
        )
        self.assertEqual(
            get_collection_id_from_ditcs(self.collections_names, "test/test/test/test"),
            None,
        )
        self.assertEqual(
            get_collection_id_from_ditcs(self.collections_names, "test2"), "test2"
        )

    def test_get_matching_ids_from_ditcs(self):
        self.assertEqual(
            ["test", "test/test", "test/test/test"],
            get_matching_ids_from_ditcs(self.collections_names, "test"),
        )
        self.assertEqual(
            ["test/test", "test/test/test"],
            get_matching_ids_from_ditcs(self.collections_names, "test/test"),
        )
        self.assertEqual(
            ["test/test/test"],
            get_matching_ids_from_ditcs(self.collections_names, "test/test/test"),
        )
        self.assertEqual(
            [],
            get_matching_ids_from_ditcs(self.collections_names, "test/test/test/test"),
        )
        self.assertEqual(
            ["test2", "test2/test2"],
            get_matching_ids_from_ditcs(self.collections_names, "test2"),
        )
