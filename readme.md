# Veza Linux Parser

This repo contains tools to help you ingest authorization metadata (users, groups, permissions) from linux servers.

There are three approaches available:

`jumpbox.py`
The basic approach here is:
* The script runs on a single box.
* The script gathers data from *n* remote machines and pushes the data back to Veza.
* The key architectural considerations here are that the host machine has access to all of the required credentials for the remote machines, and the host machine sshs (via the paramiko Python library) into the remote machines.

`parser.py`
The basic approach here is:
* The script assumes that the relevant files have already been pulled from the remote machines, and are now stored in the local `/data` folder.
* The script parses the files and pushes the data to Veza.

`agent.py`
The basic approach here is:
* The script runs as a daemon on the local machine
* The script parses the relevant files from the local machine and pushes the data to Veza.

This python script parses relevant linux files and pushes the extracted authorization metadata to the Veza cloud service.

## Veza setup

* Rename `.env_example` to `.env`
* Add your Veza url and API key to `.env`

## Veza notes

* The script will create a general bucket in Veza "linux machines"
* Each linux machine will be modeled as an individual application in Veza, under the parent "linux machines" application type.
* To help with troubleshooting, the script will by default save the json object for each app in the local directory. You can toggle this off by changing the value of `SAVE_JSON` in the "Veza config" section of the script.

[Jumpbox readme](readme_jumpbox.md)
[Parser readme]
[Agent readme]
