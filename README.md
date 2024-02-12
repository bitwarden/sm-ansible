# Bitwarden Secrets Manager Collection

Securely retrieve secrets from Bitwarden Secrets Manager and use them in your Ansible playbooks.

## Getting started

### Install dependencies

The Bitwarden Secrets Manager Collection requires the `bitwarden-sdk` package. You can install it by
running the following command:

```bash
pip install bitwarden-sdk
```

### Install the collection

You can install the Bitwarden Secrets Manager Collection by running:

```bash
ansible-galaxy collection install bitwarden.secrets
```

### Update your playbook

Before running your playbook, you need to set the `BWS_ACCESS_TOKEN` environment variable:

```bash
# the line below will prevent lines with leading spaces from being saved to bash history
export HISTCONTROL=ignorespace

# the space in the line below keeps your access token out of bash history
 export BWS_ACCESS_TOKEN=<your_access_token>
```

Alternatively, you may supply the access token as a parameter to the `bitwarden.secrets.lookup`
plugin:

<!-- prettier-ignore -->
```yaml
- name: A simple example
  hosts: localhost

  vars_prompt:
  - name: "your_access_token"
    prompt: "Enter your Bitwarden access token"
    private: yes

  vars:
    some_secret: "{{ lookup('bitwarden.secrets.lookup', '<your_secret_id>', access_token=your_access_token) }}"
```

<!-- prettier-ignore -->
> [!NOTE]
We are using a `vars_prompt` to avoid storing the access token in the playbook. While
> there are many ways to pass the access token to the lookup plugin, we recommend against storing it
> in the playbook itself.

For more information on how to use the Bitwarden Secrets Manager Collection, see the
[documentation](https://bitwarden.com/help/ansible-integration).

### Run your playbook

Once you've updated your playbook to use the Bitwarden Secrets Manager lookup plugin, you can run it
with the `ansible-playbook` command:

```bash
ansible-playbook <path_to_your_playbook.yml>
```

#### macOS

If your Ansible controller is running macOS, you may need to set the following environment variable
to avoid an error related to fork safety:

```bash
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
```

See
[running on macos as a control node](https://docs.ansible.com/ansible/latest/reference_appendices/faq.html#running-on-macos-as-a-control-node)
and [this GitHub issue](https://github.com/ansible/ansible/issues/49207) for more details.
