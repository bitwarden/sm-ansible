# Bitwarden Secrets Manager Lookup Plugin

## Install dependencies

```bash
pip install bitwarden-sdk
```

## Run

```bash
# the line below will prevent lines with leading spaces from being saved to bash history
export HISTCONTROL=ignorespace

# the space in the line below keeps your access token out of bash history
 export BWS_ACCESS_TOKEN=<your_access_token>
ansible-playbook <path_to_your_playbook>
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
