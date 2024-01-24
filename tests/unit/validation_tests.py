import unittest
import sys

sys.path.append("../..")
from plugins.lookup.bitwarden_sm import (
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
        try:
            validate_url(self.base_url, "base_url")
        except AnsibleError:
            self.fail("validate_url() raised AnsibleError unexpectedly!")

    def test_validate_url_invalid_url_throws(self):
        """validate_url() should throw for invalid urls"""
        with self.assertRaises(AnsibleError):
            validate_url("this is an invalid url", "invalid_url")

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
            try:
                LookupModule.validate_field(field)
            except AnsibleError:
                self.fail(
                    f"validate_field() raised AnsibleError unexpectedly for field: {field}"
                )

    def test_validate_field_invalid_field_throws(self):
        """validate_field() should throw for invalid fields"""
        with self.assertRaises(AnsibleError):
            LookupModule.validate_field("invalid_field")

    # validate_secret_id tests
    def test_validate_secret_id(self):
        """validate_secret_id() should succeed for valid secret ids"""
        valid_secret_id = "cdc0a886-6ad6-4136-bfd4-b04f01149173"
        try:
            LookupModule.validate_secret_id(valid_secret_id)
        except AnsibleError:
            self.fail("validate_secret_id() raised AnsibleError unexpectedly!")

    def test_validate_secret_id_invalid_secret_id_throws(self):
        """validate_secret_id() should throw for invalid secret ids"""
        invalid_secret_id = "invalid_secret_id"
        with self.assertRaises(AnsibleError):
            LookupModule.validate_secret_id(invalid_secret_id)

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

    def test_get_urls_default_urls(self):
        """if no urls are provided, use defaults"""
        api_url, identity_url = LookupModule.get_urls(None, None, None)
        self.assertEqual(api_url, BITWARDEN_API_URL)
        self.assertEqual(identity_url, BITWARDEN_IDENTITY_URL)

    def test_get_urls_base_url_provided_ignores_api_url_identity_url(self):
        """if base_url is provided, api_url and identity_url are ignored"""
        api_url, identity_url = LookupModule.get_urls(
            self.base_url, self.some_other_url, self.some_other_url
        )
        self.assertEqual(api_url, f"{self.base_url}/api")
        self.assertEqual(identity_url, f"{self.base_url}/identity")

    def test_get_urls_api_url_provided_but_identity_url_not_throws(self):
        """if api_url is provided but identity_url is not, raise AnsibleError"""
        with self.assertRaises(AnsibleError):
            LookupModule.get_urls(None, self.api_url, None)

    def test_get_urls_identity_url_provided_but_api_url_not_throws(self):
        """if identity_url is provided but api_url is not, raise AnsibleError"""
        with self.assertRaises(AnsibleError):
            LookupModule.get_urls(None, None, self.identity_url)


if __name__ == "__main__":
    unittest.main()
