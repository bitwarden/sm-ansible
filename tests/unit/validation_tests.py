import unittest
import sys

sys.path.append("../..")
from plugins.lookup.lookup import (
    AnsibleError,
    LookupModule,
    validate_url,
    BITWARDEN_API_URL,
    BITWARDEN_IDENTITY_URL,
)


class TestValidators(unittest.TestCase):
    def setUp(self):
        self.base_url = "https://example.com"
        self.api_url = f"{self.base_url}/api"
        self.identity_url = f"{self.base_url}/identity"

        self.some_other_url = (
            "https://example.test"
            # used for url construction comparison
        )

    # validate_url tests
    def test_validate_url(self):
        """validate_url() should succeed for valid urls"""
        validate_url(self.base_url, "base_url")

    def test_validate_url_invalid_url_throws(self):
        """validate_url() should throw for invalid urls"""
        self.assertRaises(
            AnsibleError, validate_url, "this is an invalid url", "invalid_url"
        )

    # validate_field tests
    def test_validate_field(self):
        """validate_field() should succeed for valid fields"""
        valid_fields = [
            "id",
            "organizationId",
            "projectId",
            "key",
            "value",
            "note",
            "creationDate",
            "revisionDate",
        ]
        for field in valid_fields:
            LookupModule.validate_field(field)

    def test_validate_field_invalid_field_throws(self):
        """validate_field() should throw for invalid fields"""
        self.assertRaises(AnsibleError, LookupModule.validate_field, "invalid_field")

    # validate_secret_id tests
    def test_validate_secret_id(self):
        """validate_secret_id() should succeed for valid secret ids"""
        valid_secret_id = "cdc0a886-6ad6-4136-bfd4-b04f01149173"
        self.assertEqual(LookupModule.validate_secret_id(valid_secret_id), None)

    def test_validate_secret_id_invalid_secret_id_throws(self):
        """validate_secret_id() should throw for invalid secret ids"""
        invalid_secret_id = "invalid_secret_id"
        self.assertRaises(
            AnsibleError, LookupModule.validate_secret_id, invalid_secret_id
        )

    # get_urls tests
    def test_get_urls_base_url(self):
        """if base_url is provided, derive api_url and identity_url from it"""
        api_url, identity_url = LookupModule.get_urls(self.base_url, None, None)
        self.assertEqual(api_url, f"{self.base_url}/api")
        self.assertEqual(identity_url, f"{self.base_url}/identity")

    def test_get_urls_api_url_identity_url(self):
        """if api_url and identity_url are provided, use them"""
        api_url, identity_url = LookupModule.get_urls(
            None, self.api_url, self.identity_url
        )
        self.assertEqual(api_url, f"{self.base_url}/api")
        self.assertEqual(identity_url, f"{self.base_url}/identity")

    def test_get_urls_base_url_provided_ignores_api_url_identity_url(self):
        """if base_url is provided, api_url and identity_url are ignored"""
        api_url, identity_url = LookupModule.get_urls(
            self.base_url, self.some_other_url, self.some_other_url
        )
        self.assertEqual(api_url, f"{self.base_url}/api")
        self.assertEqual(identity_url, f"{self.base_url}/identity")

    def test_get_urls_api_url_provided_but_identity_url_not_throws(self):
        """if api_url is provided but identity_url is not, raise AnsibleError"""
        self.assertRaises(AnsibleError, LookupModule.get_urls, None, self.api_url, None)

    def test_get_urls_identity_url_provided_but_api_url_not_throws(self):
        """if identity_url is provided but api_url is not, raise AnsibleError"""
        self.assertRaises(
            AnsibleError, LookupModule.get_urls, None, None, self.identity_url
        )


if __name__ == "__main__":
    unittest.main()
