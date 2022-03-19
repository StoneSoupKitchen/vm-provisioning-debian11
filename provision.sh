#!/bin/bash

set -euo pipefail

sudo apt-get update
sudo apt-get upgrade -y

sudo apt-get install -y curl wget openssl ca-certificates ansible

mkdir -p /tmp/provisioning
pushd /tmp/provisioning || exit

cat << EOF > ansible.cfg
[defaults]
nocows = 1
collections_path = ./collections:/etc/ansible/collections
roles_path = ./roles:/etc/ansible/roles
stdout_callback = yaml
EOF

cat << EOF > requirements.yml
---
roles:
  - name: stonesoupkitchen.apparmor
    version: v0.1.1
  - name: stonesoupkitchen.auditd
    version: v0.1.1
  - name: stonesoupkitchen.banner
    version: v0.1.1
  - name: stonesoupkitchen.chrony
    version: v0.1.1
  - name: stonesoupkitchen.cron
    version: v0.1.1
  - name: stonesoupkitchen.fail2ban
    version: v0.1.2
  - name: stonesoupkitchen.firewall
    version: v0.1.4
  - name: stonesoupkitchen.journald
    version: v0.1.1
  - name: stonesoupkitchen.logrotate
    version: v0.1.1
  - name: stonesoupkitchen.ssh
    version: v0.1.2
  - name: stonesoupkitchen.sudo
    version: v0.1.2
EOF

cat << EOF > playbook.yml
- hosts: localhost
  become: true

  roles:
    - role: stonesoupkitchen.firewall
    - role: stonesoupkitchen.ssh
    - role: stonesoupkitchen.apparmor
    - role: stonesoupkitchen.auditd
    - role: stonesoupkitchen.banner
    - role: stonesoupkitchen.chrony
    - role: stonesoupkitchen.cron
    - role: stonesoupkitchen.fail2ban
    - role: stonesoupkitchen.journald
    - role: stonesoupkitchen.logrotate
    - role: stonesoupkitchen.sudo

  tasks:
    - name: Open SSH port in firewall
      ufw:
        rule: allow
        port: "22"
        proto: tcp
EOF

ansible-galaxy install -r requirements.yml
ansible-playbook --diff playbook.yml

popd

rm -rf /tmp/provisioning
sudo apt-get purge -y --auto-remove ansible
sudo reboot

