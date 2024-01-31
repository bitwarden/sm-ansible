import base64
import unittest
import sys

sys.path.append("../..")
from plugins.lookup.lookup import AccessToken, AccessTokenInvalidError


class TestAccessToken(unittest.TestCase):
    def setUp(self):
        self.access_token_string = "0.babcb43f-fdf8-43d7-b0c4-b10000cb5949.48ojSvE7CbPVIoJWhYM8wNb654GwFn:iVl56MELslfpzHm2ayIbOw=="
        self.access_token = AccessToken(self.access_token_string)

    # AccessToken tests
    def test_access_token_valid(self):
        """access token should be parsed correctly"""
        self.assertEqual(self.access_token.access_token_version, "0")
        self.assertEqual(
            self.access_token.access_token_id, "babcb43f-fdf8-43d7-b0c4-b10000cb5949"
        )
        self.assertEqual(
            self.access_token.client_secret, "48ojSvE7CbPVIoJWhYM8wNb654GwFn"
        )
        self.assertEqual(
            self.access_token.encryption_key,
            base64.b64decode("iVl56MELslfpzHm2ayIbOw=="),
        )
        self.assertEqual(str(self.access_token), self.access_token_string)

    def test_access_token_invalid_throws(self):
        """invalid access token should throw an error"""
        access_token = "invalid_format"
        self.assertRaises(AccessTokenInvalidError, AccessToken, access_token)

    def test_invalid_version_throws(self):
        """invalid access token versions should throw an error"""
        access_token = "1.babcb43f-fdf8-43d7-b0c4-b10000cb5949.48ojSvE7CbPVIoJWhYM8wNb654GwFn:iVl56MELslfpzHm2ayIbOw=="
        self.assertRaises(AccessTokenInvalidError, AccessToken, access_token)

    def test_invalid_id_throws(self):
        """invalid access token ids should throw an error"""
        access_token = (
            "0.invalid_id:48ojSvE7CbPVIoJWhYM8wNb654GwFn:iVl56MELslfpzHm2ayIbOw"
        )
        self.assertRaises(AccessTokenInvalidError, AccessToken, access_token)

    def test_client_secret_invalid_throws(self):
        """invalid client secrets should throw an error"""
        access_token = "0.babcb43f-fdf8-43d7-b0c4-b10000cb5949.invalid_client_secret:iVl56MELslfpzHm2ayIbOw"
        self.assertRaises(AccessTokenInvalidError, AccessToken, access_token)

    def test_encryption_key_invalid_throws(self):
        """invalid encryption keys should throw an error"""
        access_token = "0.babcb43f-fdf8-43d7-b0c4-b10000cb5949.48ojSvE7CbPVIoJWhYM8wNb654GwFn:invalid_encryption_key"
        self.assertRaises(AccessTokenInvalidError, AccessToken, access_token)


if __name__ == "__main__":
    unittest.main()
