#!/usr/bin/env python

# (c) 2023, Bitwarden <hello@bitwarden.com>
# Licensed under the GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import base64
import os
import sys
from pathlib import Path
from urllib.parse import urlparse
import uuid

from ansible.errors import AnsibleError, AnsibleLookupError
from ansible.plugins.lookup import LookupBase

try:
    # noinspection PyCompatibility
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display

    display = Display()

try:
    from bitwarden_sdk import (
        BitwardenClient,
        DeviceType,
        client_settings_from_dict,
        SecretResponse,
    )
except ImportError as bitwarden_sdk:
    BW_SDK_IMPORT_ERROR = bitwarden_sdk
else:
    BW_SDK_IMPORT_ERROR = None

if BW_SDK_IMPORT_ERROR:
    raise AnsibleError(
        "The bitwarden_sm lookup plugin requires the following python modules: 'bitwarden_sdk'."
    )

DOCUMENTATION = """
name: bitwarden_sm
author: Bitwarden <hello@bitwarden.com>
version_added: "0.0.1"
short_description: Lookup secrets from Bitwarden Secrets Manager
description:
  - This lookup returns a secret from Bitwarden Secrets Manager.
options:
  _terms:
    description: 'secret id to lookup'
    required: true
    access_token:
      description: 'access token to use (default: BWS_ACCESS_TOKEN)'
      required: true
    base_url:
      description: 'base url to use (default: https://vault.bitwarden.com)'
      required: false
      default: https://vault.bitwarden.com
    api_url:
      description: 'api url to use (default: https://vault.bitwarden.com/api)'
      required: false
      default: https://vault.bitwarden.com/api
    identity_url:
      description: 'identity url to use (default: https://vault.bitwarden.com/identity)'
      required: false
      default: https://vault.bitwarden.com/identity
    state_file_dir:
      description: 'directory to store state file for authentication'
      required: false
    field:
      description: 'field to return (default: value)'
      required: false
      default: value
"""

EXAMPLES = """
- name: Lookup a secret
  ansible.builtin.debug:
    msg: "{{ lookup('bitwarden_sm', 'cdc0a886-6ad6-4136-bfd4-b04f01149173') }}"
- name: Get the note value for a secret
  ansible.builtin.debug:
    msg: "{{ lookup('bitwarden_sm', 'cdc0a886-6ad6-4136-bfd4-b04f01149173', field='note') }}"
- name: Lookup a secret using a custom access token
  ansible.builtin.debug:
    msg: ""{{ lookup('bitwarden_sm', 'cdc0a886-6ad6-4136-bfd4-b04f01149173', access_token='<your-access-token>') }}"
- name: Use a state file for authentication
  ansible.builtin.debug:
  msg: "{{ lookup('bitwarden_sm', 'cdc0a886-6ad6-4136-bfd4-b04f01149173', state_file_dir='~/.config/bitwarden-sm') }}"
"""

RETURN = """
_list:
  description: Value of the secret
  type: list
  elements: str
"""

# default URLs
BITWARDEN_BASE_URL: str = "https://vault.bitwarden.com"
BITWARDEN_API_URL: str = "https://vault.bitwarden.com/api"
BITWARDEN_IDENTITY_URL: str = "https://vault.bitwarden.com/identity"

# errors
NO_SECRET_ID_ERROR: str = "No secret ID provided"
INVALID_FIELD_ERROR: str = (
    "Invalid field: '{}'. Update this value to be one of the following: "
    "id, organizationId, projectId, key, value, note, creationDate, revisionDate"
)
INVALID_SECRET_ID_ERROR: str = "Invalid secret ID, '{}'. The secret ID must be a UUID"
INVALID_URL_ERROR: str = "Invalid {} URL, '{}'. Update this value to be a HTTPS URL"
SECRET_LOOKUP_ERROR: str = (
    "The requested secret could not be found: '{}' "
    "Please ensure that the service account has access to the secret UUID provided. "
    "Original error: {}"
)
STATE_FILE_DIR_ERROR: str = (
    "The state file directory specified could not be created: '{}' "
    "Please ensure that you have permission to create a directory at {}"
)


def is_url(url: str) -> bool:
    """Validate a URL.

    Args:
        url: The URL to validate.

    Returns:
        True if the URL is valid, False, otherwise.
    """

    try:
        result: urlparse = urlparse(url)
        return all([result.scheme in ["https"], result.netloc])
    except ValueError:
        return False


def is_valid_field(field: str) -> bool:
    """Validate a secret field.

    Args:
        field: The field to validate.

    Returns:
        True if the field is valid, False, otherwise.
    """

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
    return field in valid_fields


def validate_url(url: str, url_type: str) -> None:
    """Validate a URL.

    Args:
        url: The URL to validate.
        url_type: The type of the URL (used in error messages).

    Raises:
        AnsibleError: If the URL is not valid.
    """

    if not is_url(url):
        raise AnsibleError(INVALID_URL_ERROR.format(url_type, url))


def create_state_dir(state_file_dir: str):
    """Create the state file directory.

    Args:
        state_file_dir: The directory to create.

    Raises:
        AnsibleError: If the directory cannot be created.
    """

    try:
        display.vv(f"Creating state directory: {state_file_dir}")
        state_dir = Path(state_file_dir)
        state_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        raise AnsibleError(
            f"You do not have permission to create a directory at {state_file_dir}"
        )
    except OSError as e:
        raise AnsibleError(f"Could not create directory: {e}")
    except Exception as e:
        raise AnsibleError(f"An unexpected error occurred: {e}")


class AccessTokenInvalidError(Exception):
    pass


class AccessToken:
    def __init__(self, access_token: str):
        self._access_token = access_token
        self._access_token_version = None
        self._access_token_id = None
        self._client_secret = None
        self._encryption_key = None
        self._parse_access_token()

    def _parse_access_token(self):
        if not self._access_token:
            raise AccessTokenInvalidError("No access token provided")
        try:
            first_part, encryption_key = self._access_token.split(":")
            version, access_token_id, client_secret = first_part.split(".")
        except ValueError:
            raise AccessTokenInvalidError("Invalid access token format")

        if version != "0":
            raise AccessTokenInvalidError("Wrong version")

        try:
            uuid.UUID(access_token_id)
        except ValueError:
            raise AccessTokenInvalidError("Invalid UUID")

        try:
            self._encryption_key = base64.b64decode(encryption_key)
        except ValueError:
            raise AccessTokenInvalidError("Invalid base64")

        if len(self._encryption_key) != 16:
            raise AccessTokenInvalidError("Invalid base64 length")

        self._access_token_version = version
        self._access_token_id = access_token_id
        self._client_secret = client_secret

    @property
    def access_token_version(self) -> str:
        return self._access_token_version

    @property
    def access_token_id(self) -> str:
        return self._access_token_id

    @property
    def client_secret(self) -> str:
        return self._client_secret

    @property
    def encryption_key(self) -> bytes:
        return self._encryption_key

    @property
    def str(self) -> str:
        return self._access_token

    def __str__(self) -> str:
        return self._access_token


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs) -> list[str]:
        """
        The main method that is called when the lookup plugin is called from Ansible.

        "{{ lookup('bitwarden_sm', '877d8c62-e0eb-42b5-a22a-79be6c373bd6') }}"

        Args:
            terms (list): The list of terms passed to the lookup plugin.
            variables (dict, optional): Any variables passed to the lookup plugin.
            **kwargs: Any additional key-value arguments.

        Returns:
            list: The result of the lookup plugin.
        """

        kv_args = LookupModule.parse_args(terms)

        # Get the arguments
        secret_id = kv_args.get("secret_id")
        field = kv_args.get("field") or "value"
        api_url = kv_args.get("api_url") or BITWARDEN_API_URL
        identity_url = kv_args.get("identity_url") or BITWARDEN_IDENTITY_URL
        access_token = AccessToken(
            kv_args.get("access_token") or os.getenv("BWS_ACCESS_TOKEN")
        )
        state_file_dir = kv_args.get("state_file_dir")

        self.validate_args(secret_id, field)
        return self.get_secret_data(
            access_token,
            secret_id,
            field,
            api_url,
            identity_url,
            state_file_dir,
        )

    @staticmethod
    def parse_args(args) -> dict:
        """
        Parse key-value arguments.

        Args:
            args (list): The arguments to parse.

        Returns:
            dict: A dictionary where the keys are the argument names and the values are the argument values.
        """
        kv_args = {}

        for arg in args:
            if "=" in arg:
                key, value = arg.split("=", 1)
                kv_args[key] = value
            else:
                kv_args["secret_id"] = arg

        if not kv_args.get("secret_id"):
            raise AnsibleError(NO_SECRET_ID_ERROR)

        return kv_args

    @staticmethod
    def get_urls(kwargs) -> tuple[str, str, str]:
        """
        Get the Bitwarden environment URLs.

        Args:
            kwargs (dict): The kwargs passed to the lookup plugin.

        Returns:
            tuple[str, str, str]: The base URL, API URL, and Identity URL.
        """

        base_url: str = kwargs.get("base_url", BITWARDEN_BASE_URL).rstrip("/")
        if base_url != BITWARDEN_BASE_URL:
            api_url: str = f"{base_url}/api"
            identity_url: str = f"{base_url}/identity"
        else:
            api_url: str = kwargs.get("api_url", BITWARDEN_API_URL).rstrip("/")
            identity_url: str = kwargs.get(
                "identity_url", BITWARDEN_IDENTITY_URL
            ).rstrip("/")
        return base_url, api_url, identity_url

    @staticmethod
    def get_env_and_args(kwargs) -> tuple[AccessToken, str, str, str]:
        """
        Get the access token, secret ID, field, and state file directory.

        Args:
            kwargs (dict): The kwargs passed to the lookup plugin.

        Returns:
            tuple[AccessToken, str, str, str]: The access token, secret ID, field, and state file directory.
        """

        access_token: AccessToken = AccessToken(
            kwargs.get("access_token") or os.getenv("BWS_ACCESS_TOKEN")
        )
        secret_id: str = kwargs.get("secret_id")
        field: str = kwargs.get("field", "value")
        state_file_dir: str = kwargs.get("state_file_dir")
        display.vv(f"Secret ID: {secret_id}")
        display.vv(f"Field: {field}")
        display.vv(f"State file dir: {state_file_dir}")
        return access_token, secret_id, field, state_file_dir

    @staticmethod
    def get_state_file_path(state_file_dir: str, access_token_id: str) -> str:
        """
        Get the state file path.

        Args:
            state_file_dir (str): The state file directory.
            access_token_id (str): The access token ID.

        Returns:
            str: The state file path.
        """

        return os.path.join(state_file_dir, access_token_id)

    def validate_args(self, secret_id, field) -> None:
        self.validate_secret_id(secret_id)
        self.validate_field(field)

    @staticmethod
    def validate_urls(base_url, api_url, identity_url) -> None:
        display.v("Parsing Bitwarden environment URL")
        validate_url(base_url, "base")
        validate_url(api_url, "API")
        validate_url(identity_url, "Identity")

    @staticmethod
    def validate_secret_id(secret_id) -> None:
        """
        Check that the secret_id is a valid UUID.

        Args:
            secret_id (str): The secret_id to validate.

        Raises:
            AnsibleError: If the secret_id is not a valid UUID.
        """

        display.v("Parsing secret ID")
        try:
            uuid.UUID(secret_id)
        except ValueError as e:
            display.error(INVALID_SECRET_ID_ERROR.format(secret_id))
            raise AnsibleError(INVALID_SECRET_ID_ERROR.format(secret_id)) from e

    @staticmethod
    def validate_field(field) -> None:
        """
        Check that the secret field is valid.

        Args:
            field (str): The field to validate.

        Raises:
            AnsibleError: If the field is not valid.
        """

        display.v("Validating field argument")
        if not is_valid_field(field):
            display.error(INVALID_FIELD_ERROR.format(field))
            raise AnsibleError(INVALID_FIELD_ERROR.format(field))

    @staticmethod
    def get_secret_data(
        access_token,
        secret_id,
        field,
        api_url,
        identity_url,
        state_file_dir,
    ) -> list[str]:
        """
        Retrieves the secret data.

        Args:
            access_token (AccessToken): The access token.
            secret_id (str): The secret ID.
            field (str): The field.
            api_url (str): The API URL.
            identity_url (str): The Identity URL.
            state_file_dir (str): The state file directory.

        Returns:
            list[str]: The secret data.

        Raises:
            AnsibleError: If the state file directory cannot be created.
            AnsibleError: If the secret cannot be found.

        """

        display.v("Authenticating with Bitwarden")
        client: BitwardenClient = BitwardenClient(
            client_settings_from_dict(
                {
                    "apiUrl": api_url,
                    "deviceType": DeviceType.SDK,
                    "identityUrl": identity_url,
                    "userAgent": "bitwarden/sm-ansible",
                }
            )
        )

        try:
            if not state_file_dir:
                client.access_token_login(access_token.str)
            else:
                create_state_dir(state_file_dir)
                state_file = str(Path(state_file_dir, access_token.access_token_id))
                client.access_token_login(access_token.str, state_file)
        except AnsibleError as e:
            display.error(STATE_FILE_DIR_ERROR.format(e, state_file_dir))
            raise AnsibleError(STATE_FILE_DIR_ERROR.format(e, state_file_dir)) from e

        try:
            secret: SecretResponse = client.secrets().get(secret_id)
            secret_data: str = secret.to_dict()["data"][field]
            return [secret_data]
        except Exception as e:
            error_message = f"{SECRET_LOOKUP_ERROR.format(secret_id)}: {e}"
            display.error(error_message)
            raise AnsibleLookupError(error_message) from e


if __name__ == "__main__":
    print(
        LookupModule().run(
            sys.argv[1:],
            None,
            field="value",
            base_url=BITWARDEN_BASE_URL,
            api_url=BITWARDEN_API_URL,
            identity_url=BITWARDEN_IDENTITY_URL,
            access_token=None,
        )[0]
    )
