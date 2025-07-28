# Veza Linux Connector - Jumpbox

## How it works

The script opens the file `.ssh/config` on the local machine and looks for hosts.

For each host, the script connects to the host and retrieves authorization metadata:

* users in the user directory (`/etc/passwd`)
    * only users who have ssh privileges
* users who have authenticated via ssh against the host (`/var/log`)
* users who can sudo
* groups (`/etc/group`)

After the script gathers all of the authorization metadata from all of the hosts, it pushes the data to Veza.

## Authentication to linux hosts

The script will attempt to authenticate against a host in the method dictated by the `.ssh/config` file.

In the case of password authentication, you can store the password in the `.env` file, and the script will look for the password there.

{host_label}: {password}

The script expects to have `sudo` privileges on the host(s) that it connects to.

> **Note:** `sudo` privileges are not typically required to read the `/etc/passwd` file, but `sudo` is typically required to read authentication logs.

## Setup

Set the path for `SSH_CONFIG_PATH` in `config.json`.

Other values that you can configure are:

|Setting|Default|Desc|
|---------|---------|------|
|IGNORE_HOSTS|[*]|A list of hosts in your `.ssh/config` file that should be ignored.|
|IGNORE_USERS|[]|A list of users to ignore|
|MAX_LOGS|5|The maximum number of log files that should be parsed.|
|SSH_CONFIG_PATH||The path to your `.ssh/config` file|

## Run

`pip install -r requirements.txt`

`python3 jumpbox.py`
