#!/bin/bash

set -euo pipefail

# Create a temporary working directory.
mkdir -p /tmp/provisioning
pushd /tmp/provisioning || exit

# Update the base system.
sudo apt-get update
sudo apt-get upgrade -y

# Install helper utilities.
sudo apt-get install -y curl wget openssl ca-certificates

# Install and configure firewall.
sudo apt-get install -y ufw
sudo ufw enable
sudo ufw allow ssh

# Install and configure ssh.
sudo apt-get install -y openssh-server

cat << EOF > sshd.conf
# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Protocol 2

Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256

# Logging
#SyslogFacility AUTH
LogLevel VERBOSE

# Authentication
LoginGraceTime 60
PermitRootLogin no
# Change to yes if you don't trust ~/.ssh/known_hosts for
#StrictModes yes
MaxAuthTries 4
MaxSessions 10

#PubkeyAuthentication yes

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
#AuthorizedKeysFile	.ssh/authorized_keys .ssh/authorized_keys2

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
PasswordAuthentication no
PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM yes

#AllowAgentForwarding yes
AllowTcpForwarding no
#GatewayPorts no
X11Forwarding no
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
#TCPKeepAlive yes
PermitUserEnvironment no
#Compression delayed
ClientAliveInterval 300
ClientAliveCountMax 0
#UseDNS no
#PidFile /var/run/sshd.pid
MaxStartups 10:30:60
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

Banner /etc/issue.net

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem	sftp	/usr/lib/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#	X11Forwarding no
#	AllowTcpForwarding no
#	PermitTTY no
#	ForceCommand cvs server
#   ClientAliveInterval 120
EOF
sudo sshd -t -f sshd.conf
sudo cp sshd.conf /etc/ssh/sshd_conf
sudo chown root:root /etc/ssh/sshd_config
sudo chmod 0600 /etc/ssh/sshd_config

#sudo systemctl enable sshd
#sudo systemctl start sshd

# Install and configure apparmor.
sudo apt-get install -y apparmor apparmor-utils

# Install and configure auditd.
sudo apt-get install -y auditd audispd-plugins

cat << EOF > auditd.conf
#
# This file controls the configuration of the audit daemon
#
##krb5_key_file = /etc/audit/audit.key
##name = mydomain
##tcp_client_ports = 1024-65535
##tcp_listen_port = 60
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_error_action = SUSPEND
disk_full_action = SUSPEND
disp_qos = lossy
dispatcher = /sbin/audispd
distribute_network = no
enable_krb5 = no
flush = INCREMENTAL_ASYNC
freq = 50
krb5_principal = auditd
local_events = yes
log_file = /var/log/audit/audit.log
log_format = RAW
log_group = adm
max_log_file = 8
max_log_file_action = ROTATE
name_format = NONE
num_logs = 5
priority_boost = 4
space_left = 75
space_left_action = SYSLOG
tcp_client_max_idle = 0
tcp_listen_queue = 5
tcp_max_per_addr = 1
use_libwrap = yes
verify_email = yes
write_logs = yes
EOF
sudo cp auditd.conf /etc/audit/auditd.conf
sudo chown root:root /etc/audit/auditd.conf
sudo chmod 0640 /etc/audit/auditd.conf

sudo systemctl enable auditd
sudo systemctl start auditd

# Install and configure banner.
cat << EOF > banner
WARNING: Unauthorized access to this system is forbidden and will be
prosecuted by law. By accessing this system, you agree that your actions
may be monitored if unauthorized usage is suspected.
EOF
sudo cp banner /etc/motd
sudo cp banner /etc/issue
sudo cp banner /etc/issue.net
sudo chown root:root /etc/motd
sudo chown root:root /etc/issue
sudo chown root:root /etc/issue.net
sudo chmod 0644 /etc/motd
sudo chmod 0644 /etc/issue
sudo chmod 0644 /etc/issue.net

# Install and configure chrony.
sudo apt-get install -y chrony

cat << EOF > chrony.conf
# Welcome to the chrony configuration file. See chrony.conf(5) for more
# information about usuable directives.
pool 2.debian.pool.ntp.org iburst

# This directive specify the location of the file containing ID/key pairs for
# NTP authentication.
keyfile /etc/chrony/chrony.keys

# This directive specify the file into which chronyd will store the rate
# information.
driftfile /var/lib/chrony/chrony.drift

# Uncomment the following line to turn logging on.
#log tracking measurements statistics

# Log files location.
logdir /var/log/chrony

# Stop bad estimates upsetting machine clock.
maxupdateskew 100.0

# This directive enables kernel synchronisation (every 11 minutes) of the
# real-time clock. Note that it can’t be used along with the 'rtcfile' directive.
rtcsync

# Step the system clock instead of slewing it if the adjustment is larger than
# one second, but only in the first three clock updates.
makestep 1 3
EOF
sudo cp chrony.conf /etc/chrony/chrony.conf
sudo chown root:root /etc/chrony/chrony.conf
sudo chmod 0644 /etc/chrony/chrony.conf

#sudo systemctl enable chronyd
#sudo systemctl start chronyd

# Install and configure cron.
sudo apt-get install -y cron at

sudo touch /etc/cron.allow
sudo touch /etc/at.allow
sudo rm -f /etc/cron.deny
sudo rm -f /etc/at.deny
sudo chown root:root /etc/crontab
sudo chown root:root /etc/cron.hourly
sudo chown root:root /etc/cron.daily
sudo chown root:root /etc/cron.weekly
sudo chown root:root /etc/cron.monthly
sudo chown root:root /etc/cron.d
sudo chown root:root /etc/cron.allow
sudo chown root:root /etc/at.allow
sudo chmod 0600 /etc/crontab
sudo chmod 0700 /etc/cron.hourly
sudo chmod 0700 /etc/cron.daily
sudo chmod 0700 /etc/cron.weekly
sudo chmod 0700 /etc/cron.monthly
sudo chmod 0700 /etc/cron.d
sudo chmod 0640 /etc/cron.allow
sudo chmod 0640 /etc/at.allow

sudo systemctl enable cron
sudo systemctl start cron
sudo systemctl enable atd
sudo systemctl start atd

# Install and configure fail2ban.
sudo apt-get install -y fail2ban

cat << EOF > fail2ban.conf
# Fail2Ban main configuration file
#
# Comments: use '#' for comment lines and ';' (following a space) for inline comments
#
# Changes:  in most of the cases you should not modify this
#           file, but provide customizations in fail2ban.local file, e.g.:
#
# [Definition]
# loglevel = DEBUG
#
[Definition]
loglevel = INFO
logtarget = /var/log/fail2ban.log
syslogsocket = auto
socket = /var/run/fail2ban/fail2ban.sock
pidfile = /var/run/fail2ban/fail2ban.pid
dbfile = /var/lib/fail2ban/fail2ban.sqlite3
dbpurgeage = 1d
EOF

cat << EOF > jail.local
[DEFAULT] 
ignoreip = 127.0.0.1/8 ::1
bantime  = 86400
findtime  = 600
maxretry = 3
banaction = iptables-multiport
backend = systemd

[sshd] 
enabled = true
port = ssh
filter = sshd
EOF

sudo cp fail2ban.conf /etc/fail2ban/fail2ban.conf
sudo cp jail.local /etc/fail2ban/jail.local
sudo chown root:root /etc/fail2ban/fail2ban.conf
sudo chown root:root /etc/fail2ban/fail2ban.d
sudo chown root:root /etc/fail2ban/jail.conf
sudo chown root:root /etc/fail2ban/jail.d
sudo chown root:root /etc/fail2ban/jail.local
sudo chmod 0644 /etc/fail2ban/fail2ban.conf
sudo chmod 0755 /etc/fail2ban/fail2ban.d
sudo chmod 0644 /etc/fail2ban/jail.conf
sudo chmod 0755 /etc/fail2ban/jail.d
sudo chmod 0644 /etc/fail2ban/jail.local

sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Install and configure journald.
sudo apt-get install -y systemd-journal-remote

cat << EOF > journald.conf
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
# Entries in this file show the compile time defaults.
# You can change settings by editing this file.
# Defaults can be restored by simply deleting this file.
#
# See journald.conf(5) for details.

[Journal]
Storage=persistent
Compress=yes
#Seal=yes
#SplitMode=uid
#SyncIntervalSec=5m
#RateLimitIntervalSec=30s
#RateLimitBurst=10000
#SystemMaxUse=
#SystemKeepFree=
#SystemMaxFileSize=
#SystemMaxFiles=100
#RuntimeMaxUse=
#RuntimeKeepFree=
#RuntimeMaxFileSize=
#RuntimeMaxFiles=100
#MaxRetentionSec=
#MaxFileSec=1month
ForwardToSyslog=yes
#ForwardToKMsg=no
#ForwardToConsole=no
#ForwardToWall=yes
#TTYPath=/dev/console
#MaxLevelStore=debug
#MaxLevelSyslog=debug
#MaxLevelKMsg=notice
#MaxLevelConsole=info
#MaxLevelWall=emerg
#LineMax=48K
#ReadKMsg=yes
EOF
sudo cp journald.conf /etc/systemd/journald.conf
sudo chown root:root /etc/systemd/journald.conf
sudo chmod 0644 /etc/systemd/journald.conf

sudo systemctl enable systemd-journald
sudo systemctl start systemd-journald

# Install and configure logrotate.
sudo apt-get install -y logrotate

cat << EOF > logrotate.conf
# see "man logrotate" for details
# rotate log files weekly
weekly

# keep 4 weeks worth of backlogs
rotate 4

# create new (empty) log files after rotating old ones
create

# use date as a suffix of the rotated file
#dateext

# uncomment this if you want your log files compressed
#compress

# packages drop log rotation information into this directory
include /etc/logrotate.d

# system-specific logs may be also be configured here.
EOF
sudo cp logrotate.conf /etc/logrotate.conf
sudo chown root:root /etc/logrotate.conf
sudo chown root:root /etc/logrotate.d
sudo chmod 0644 /etc/logrotate.conf
sudo chmod 0755 /etc/logrotate.d

# Install and configure sudo.
sudo apt-get install -y sudo

cat << EOF > sudoers
# Defaults specification

Defaults    !visiblepw
Defaults    always_set_home
Defaults    match_group_by_gid
Defaults    always_query_group_plugin
Defaults    env_reset
Defaults    env_keep =  "COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS"
Defaults    env_keep += "MAIL QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE"
Defaults    env_keep += "LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES"
Defaults    env_keep += "LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE"
Defaults    env_keep += "LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY"
Defaults    secure_path = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Defaults    logfile = "/var/log/sudo.log"
Defaults    use_pty

## Allow root to run any commands anywhere
root	ALL=(ALL) 	ALL

## Read drop-in files from /etc/sudoers.d (the # here does not mean a comment)
#includedir /etc/sudoers.d
EOF
sudo visudo -cf sudoers
sudo cp sudoers /etc/sudoers
sudo chown root:root /etc/sudoers
sudo chown root:root /etc/sudoers.d
sudo chmod 0440 /etc/sudoers
sudo chmod 0750 /etc/sudoers.d

# Clean up.
popd
rm -rf /tmp/provisioning
sudo apt-get purge -y --auto-remove
