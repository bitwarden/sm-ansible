#!/usr/bin/env python

# (c) 2024, Bitwarden <hello@bitwarden.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
name: lookup
author:
  - Bitwarden (@bitwarden) <hello@bitwarden.com>
version_added: "1.0.0"
short_description: Lookup secrets from Bitwarden Secrets Manager
description:
  - This lookup returns a secret from Bitwarden Secrets Manager.
options:
  _terms:
    description: Secret ID to lookup
    required: True
  access_token:
    description: Access token to use
    default: $BWS_ACCESS_TOKEN
    env:
      - name: BWS_ACCESS_TOKEN
    required: True
    type: string
  base_url:
    description: Base url to use. If provided, api_url and identity_url will be ignored.
    default: https://vault.bitwarden.com
    required: False
    type: string
  api_url:
    description: API url to use. If provided, identity_url must also be provided.
    default: https://api.bitwarden.com
    required: False
    type: string
  identity_url:
    description: Identity url to use. If provided, api_url must also be provided.
    default: https://identity.bitwarden.com
    required: False
    type: string
  state_file_dir:
    description: Directory to store state file for authentication.
    required: False
    type: string
  field:
    description: Field to return from the secret.
    default: value
    required: False
    type: string
"""

EXAMPLES = """
- name: Lookup a secret
  ansible.builtin.debug:
    msg: "{{ lookup('bitwarden.secrets.lookup', 'cdc0a886-6ad6-4136-bfd4-b04f01149173') }}"
- name: Get the note value for a secret
  ansible.builtin.debug:
    msg: "{{ lookup('bitwarden.secrets.lookup', 'cdc0a886-6ad6-4136-bfd4-b04f01149173', field='note') }}"
- name: Lookup a secret using a custom access token
  ansible.builtin.debug:
    msg: "{{ lookup('bitwarden.secrets.lookup', 'cdc0a886-6ad6-4136-bfd4-b04f01149173', access_token='<your-access-token>') }}"
- name: Use a state file for authentication
  ansible.builtin.debug:
    msg: "{{ lookup('bitwarden.secrets.lookup', 'cdc0a886-6ad6-4136-bfd4-b04f01149173', state_file_dir='~/.config/bitwarden-sm') }}"
"""

RETURN = """
_list:
  description: Value of the secret
  type: list
  elements: str
"""

import base64
import os
from pathlib import Path
from urllib.parse import urlparse
import uuid

from ansible.errors import AnsibleError, AnsibleLookupError
from ansible.plugins.lookup import LookupBase
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
        "The bitwarden.secrets.lookup plugin requires the following python modules: 'bitwarden-sdk'."
    )

# default URLs
BITWARDEN_API_URL: str = "https://api.bitwarden.com"
BITWARDEN_IDENTITY_URL: str = "https://identity.bitwarden.com"

# errors
NO_SECRET_ID_ERROR: str = "No secret ID provided"
API_IDENTITY_URL_ERROR: str = (
    "You must provide either a base_url, or an api_url AND identity_url. "
    "You provided: api_url: {}, identity_url: {}"
)
INVALID_FIELD_ERROR: str = (
    "Invalid field: '{}'. Update this value to be one of the following: "
    "id, organizationId, projectId, key, value, note, creationDate, revisionDate"
)
INVALID_SECRET_ID_ERROR: str = "Invalid secret ID, '{}'. The secret ID must be a UUID"
INVALID_URL_ERROR: str = (
    "URL must start with http:// or https://, the provided {} URL is: '{}'"
)
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
    try:
        result: urlparse = urlparse(url)
        return all([result.scheme in ["http", "https"], result.netloc])
    except ValueError:
        return False


def is_valid_field(field: str) -> bool:
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
    if not is_url(url):
        raise AnsibleError(INVALID_URL_ERROR.format(url_type, url))


def create_state_dir(state_file_dir: str):
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
    # pylint: disable=used-before-assignment
    def __init__(self, access_token: str):
        self._access_token = access_token
        self._access_token_version = None
        self._access_token_id = None
        self._client_secret = None
        self._encryption_key = None
        self._parse_access_token()

    # pylint: enable=used-before-assignment

    def _parse_access_token(self):
        if not self._access_token:
            display.error("No access token provided")
            raise AccessTokenInvalidError("No access token provided")
        try:
            first_part, encryption_key = self._access_token.split(":")
            version, access_token_id, client_secret = first_part.split(".")
        except ValueError:
            display.error("Invalid access token format")
            raise AccessTokenInvalidError("Invalid access token format")

        if version != "0":
            display.error("Wrong access token version")
            raise AccessTokenInvalidError("Wrong access token version")

        try:
            uuid.UUID(access_token_id)
        except ValueError:
            display.error("Invalid access token UUID")
            raise AccessTokenInvalidError("Invalid access token UUID")

        try:
            self._encryption_key = base64.b64decode(encryption_key)
        except ValueError:
            display.error(
                "Invalid access token envryption key. Should be base64-encoded"
            )
            raise AccessTokenInvalidError(
                "Invalid access token envryption key. Should be base64-encoded"
            )

        if len(self._encryption_key) != 16:
            display.error("Invalid base64 length for encryption key")
            raise AccessTokenInvalidError("Invalid base64 length for encryption key")

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
        # Set the options
        self.set_options(var_options=variables, direct=kwargs)

        # Get the options
        if not terms:
            raise AnsibleError("No secret_id provided")
        secret_id = terms[0]
        self.validate_secret_id(secret_id)

        field = self.get_option("field") or "value"
        self.validate_field(field)

        base_url = self.get_option("base_url")
        api_url = self.get_option("api_url")
        identity_url = self.get_option("identity_url")
        api_url, identity_url = self.get_urls(base_url, api_url, identity_url)
        self.validate_urls(api_url, identity_url)

        access_token = AccessToken(
            self.get_option("access_token") or os.getenv("BWS_ACCESS_TOKEN")
        )
        state_file_dir = self.get_option("state_file_dir")

        display.vv(f"secret_id: {secret_id}")
        display.vv(f"field: {field}")
        display.vv(f"base_url: {base_url}")
        display.vv(f"api_url: {api_url}")
        display.vv(f"identity_url: {identity_url}")
        display.vv(f"state_file_dir: {state_file_dir}")

        return self.get_secret_data(
            access_token,
            secret_id,
            field,
            api_url,
            identity_url,
            state_file_dir,
        )

    @staticmethod
    def get_urls(base_url: str, api_url: str, identity_url: str) -> tuple[str, str]:
        if base_url:
            base_url = base_url.rstrip("/")
            api_url = f"{base_url}/api"
            identity_url = f"{base_url}/identity"
        elif api_url and identity_url:
            return api_url, identity_url
        elif not base_url and not api_url and not identity_url:
            api_url = BITWARDEN_API_URL
            identity_url = BITWARDEN_IDENTITY_URL
        else:
            display.error(API_IDENTITY_URL_ERROR.format(api_url, identity_url))
            raise AnsibleError(
                API_IDENTITY_URL_ERROR.format(api_url, identity_url)
            ) from None
        return api_url, identity_url

    @staticmethod
    def validate_urls(api_url, identity_url) -> None:
        display.v("Parsing Bitwarden environment URL")
        validate_url(api_url, "API")
        validate_url(identity_url, "Identity")

    @staticmethod
    def validate_secret_id(secret_id) -> None:
        display.v("Parsing secret ID")
        try:
            uuid.UUID(secret_id)
        except ValueError as e:
            display.error(INVALID_SECRET_ID_ERROR.format(secret_id))
            raise AnsibleError(INVALID_SECRET_ID_ERROR.format(secret_id)) from e

    @staticmethod
    def validate_field(field) -> None:
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
