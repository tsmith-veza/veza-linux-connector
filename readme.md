# Veza Linux Connector

This project enables you to pull authorization metadata from linux hosts and push that authorization metadata to Veza for visualization and analysis.

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

The script expects to have `sudo` privileges on the host that it connects to.

> **Note:** `sudo` privileges are not typically required to read the /etc/passwd file, but `sudo` is typically required to read authentication logs.

## Setup

Set the path for `SSH_CONFIG_PATH` in `config.json`.

Other values that you can configure are:

|Setting|Default|Desc|
|---------|---------|------|
|IGNORE_HOSTS|[*]|A list of hosts in your `.ssh/config` file that should be ignored.|
|IGNORE_USERS|[]|A list of users to ignore|
|MAX_LOGS|5|The maximum number of log files that should be parsed.|
|SSH_CONFIG_PATH||The path to your `.ssh/config` file|

## Veza setup

* Rename `.env_example` to `.env`
* Add your Veza url and API key to `.env`

## Veza notes

* Every linux machine will be modeled as an application in Veza.
* To help with troubleshooting, the script will by default save the json object for each app in the local directory. You can toggle this off by changing the value of `SAVE_JSON` in the "Veza config" section of the script.

## Run

`pip install -r requirements.txt`

`python3 parse.py`
