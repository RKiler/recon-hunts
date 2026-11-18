import hashlib
import unittest

from continuous_recon import MAX_INDEXED_PARAMETER_NAME_BYTES, storage_parameter_name


class ParameterNameStorageTests(unittest.TestCase):
    def test_normal_name_is_preserved(self) -> None:
        self.assertEqual(storage_parameter_name("return_to"), "return_to")

    def test_name_over_255_characters_is_preserved(self) -> None:
        name = "a" * 400
        self.assertEqual(storage_parameter_name(name), name)

    def test_pathological_name_is_bounded_and_fingerprinted(self) -> None:
        name = "x" * 5000
        stored = storage_parameter_name(name)
        self.assertLessEqual(len(stored.encode("utf-8")), MAX_INDEXED_PARAMETER_NAME_BYTES)
        self.assertTrue(stored.endswith(f"[sha256:{hashlib.sha256(name.encode()).hexdigest()}]"))

    def test_multibyte_name_respects_byte_limit(self) -> None:
        stored = storage_parameter_name("\u00e9" * 2000)
        self.assertLessEqual(len(stored.encode("utf-8")), MAX_INDEXED_PARAMETER_NAME_BYTES)


if __name__ == "__main__":
    unittest.main()
