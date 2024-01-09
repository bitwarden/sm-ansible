# Bitwarden Secrets Manager Lookup Plugin

## Install dependencies

```bash
pip install bitwarden_sdk
```

## Run

```bash
export HISTCONTROL=ignorespace # to avoid storing access token in bash history
 export BWS_ACCESS_TOKEN=<your_access_token> # the space keeps this out of bash history
ansible-playbook examples/test.yml
```

### macOS

On macOS, you may need to set the following environment variable to avoid an error related to fork
safety:

```bash
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
```

See
[running on macos as a control node](https://docs.ansible.com/ansible/latest/reference_appendices/faq.html#running-on-macos-as-a-control-node)
and [this GitHub issue](https://github.com/ansible/ansible/issues/49207) for more details.

## Execute as a standalone script

```bash
python ./plugins/lookup/bitwarden_sm.py <secret_id> base_url=<vault_url>
```
