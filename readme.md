# Veza Linux Parser

This repo contains tools to help you ingest authorization metadata (users, groups, permissions) from linux hosts.

The basic pattern is that you point the script to the relevant files (`passwd`, `sudoers`, etc.) from your host, and the parser parses those files and creates a Veza application to represent that machine and all of its users. 

## Setup

### Veza setup
* Copy the `.env_example` file to `.env`
* Update the values for `VEZA_URL` and `VEZA_API_KEY`

### Data setup
Each host should have its own subdirectory in the data directory.

An example data set for `host01` is included.

For each host to be included in Veza, create a subdirectory with the name of the host, and then add files and subdirectories after the pattern provided in the example `host01` directory.

### Python setup

pip install -r requirements.txt

## Running the app

`python3 parser.py`

## Veza data modeling notes

* The script will create a general bucket in Veza called "linux_hosts"
* Each linux machine will be modeled as an individual application in Veza, under the parent "linux machines" application type.
* To help with troubleshooting, the script will by default save the json object for each app in the local directory. You can toggle this off by changing the value of `SAVE_JSON` in the "Veza config" section of the script.

## Linux data parsing notes


