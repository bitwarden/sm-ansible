#!/usr/bin/env python

# (c) 2023, Bitwarden <support@bitwarden.com>
# The LICENSE_NAME (see LICENSE or
# https://link-to-license.org/)
#
from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError

import os
import sys

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

try:
    # noinspection PyCompatibility
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display

    display = Display()

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
    ansible.builtin.field:
      description: 'field to return (default: value)'
      required: false
      default: value
    ansible.builtin.base_url:
      description: 'base url to use (default: https://vault.bitwarden.com)'
      required: false
      default: https://vault.bitwarden.com
    ansible.builtin.api_url:
      description: 'api url to use (default: https://vault.bitwarden.com/api)'
      required: false
      default: https://vault.bitwarden.com/api
    ansible.builtin.identity_url:
      description: 'identity url to use (default: https://vault.bitwarden.com/identity)'
      required: false
      default: https://vault.bitwarden.com/identity
"""

EXAMPLES = """
- name: Lookup a secret
  ansible.builtin.debug:
    msg: "{{ lookup('bitwarden_sm', 'cdc0a886-6ad6-4136-bfd4-b04f01149173') }}"
- name: Get the note value for a secret
  ansible.builtin.debug:
    msg: "{{ lookup('bitwarden_sm', 'cdc0a886-6ad6-4136-bfd4-b04f01149173', field='note') }}"
"""

RETURN = """
_list:
  description: Value of the secret
  type: list
  elements: str
"""

BITWARDEN_BASE_URL: str = "https://vault.bitwarden.com"
BITWARDEN_API_URL: str = "https://vault.bitwarden.com/api"
BITWARDEN_IDENTITY_URL: str = "https://vault.bitwarden.com/identity"


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs) -> list[str]:
        if not terms:
            raise AnsibleError("No secret id provided.")

        for term in terms:
            if "=" in term:
                key, value = term.split("=")
                kwargs[key] = value
            else:
                kwargs["secret_id"] = term

        base_url: str = (kwargs.get("base_url") or BITWARDEN_BASE_URL).rstrip("/")

        if base_url != BITWARDEN_BASE_URL:
            api_url: str = base_url + "/api"
            identity_url: str = base_url + "/identity"
        else:
            api_url: str = (kwargs.get("api_url") or BITWARDEN_API_URL).rstrip("/")
            identity_url: str = (
                kwargs.get("identity_url") or BITWARDEN_IDENTITY_URL
            ).rstrip("/")

        access_token: str = os.getenv("BWS_ACCESS_TOKEN")
        secret_id: str = kwargs.get("secret_id")
        field: str = kwargs.get("field", "value")

        client: BitwardenClient = BitwardenClient(
            client_settings_from_dict(
                {
                    "apiUrl": api_url,
                    "deviceType": DeviceType.SDK,
                    "identityUrl": identity_url,
                    "userAgent": "Python",
                }
            )
        )

        client.access_token_login(access_token)

        secret: SecretResponse = client.secrets().get(secret_id)
        secret_data: str = secret.to_dict()["data"][field]

        return [secret_data]


if __name__ == "__main__":
    LookupModule().run(
            sys.argv[1:],
            None,
            field="value",
            base_url=BITWARDEN_BASE_URL,
            api_url=BITWARDEN_API_URL,
            identity_url=BITWARDEN_IDENTITY_URL,
        )
