#!/bin/bash

# Whitelisted Accounts
WHITELIST="da1, krbtgt, cucumber, WDAGUtilityAccount, DefaultAccount"

# Get current users from Windows using Ansible
users=$(ansible windows -i /Windows-Scripts/ansible/inventory/inventory.yml -m win_command -a "net user" | grep -oP '^[^\s]+(?=\s+Account') | sort -u)

# Loop through found users
for user in $users; do
  if [[ ! ",$WHITELIST," =~ ",$user," ]]; then
    echo "{\"username\": \"$user\", \"status\": \"unauthorized\"}" > /tmp/user_alert.json
    break
  fi
done
