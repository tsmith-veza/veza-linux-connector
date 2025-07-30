#!env python3

import json
import logging
import os
import re
import sys

from datetime import datetime, timezone
from dotenv import load_dotenv
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import OAAPropertyType, CustomApplication, OAAPermission
from pysudoers import Sudoers

#######################################
# Veza config

load_dotenv()

PROVIDER_NAME = os.getenv('PROVIDER_NAME') # aka application type
VEZA_API_KEY = os.getenv('VEZA_API_KEY')
VEZA_URL = os.getenv('VEZA_URL')

SAVE_JSON = True

########################################

DATA_PATH = './data'

GROUP_FILE_FIELD_COUNT = int(os.getenv('GROUP_FILE_FIELD_COUNT', 4))
PASSWD_FILE_FIELD_COUNT = int(os.getenv('PASSWD_FILE_FIELD_COUNT', 7))

with open('usernames_to_ignore.json', 'r') as f:

    USERNAMES_TO_IGNORE = json.load(f)

USERNAMES_TO_IGNORE_LOWER = [u.lower() for u in USERNAMES_TO_IGNORE]

########################################

# logging.basicConfig(level=logging.DEBUG)

logging.basicConfig(level=logging.INFO)

log = logging.getLogger()

########################################
# OS utilities

def format_rfc3339(timestamp_str):
    """
    Converts various timestamp formats to RFC 3339 (ISO 8601).
    Handles:
      - "2025-03-15T14:41:22" (already RFC 3339)
      - "Mar 15 14:41:22" (syslog format, assumes current year)
    """
    
    try:
        # Try parsing ISO 8601 (RFC 3339) format
        dt = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        try:
            # Try parsing traditional syslog format (assume current year)
            dt = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            dt = dt.replace(year=datetime.now().year)  # Add current year
        except ValueError:
            raise ValueError(f"Unsupported timestamp format: {timestamp_str}")

    dt = dt.replace(tzinfo=timezone.utc)  # Ensure UTC timezone
    return dt.isoformat()  # Convert to RFC 3339 format

def get_files_os(path):
    """
    Returns a list of files (not subdirectories) in the specified directory.

    Args:
        path (str): The path to the directory to scan.

    Returns:
        list: A list of file names (strings) found in the directory.
              Returns an empty list if the directory is not found,
              or if there's a permission error, after printing an error message.
    """
    files = []
    try:
        # Iterate over all items (files and directories) in the given path
        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            # Check if the item is a file (and not a directory)
            if os.path.isfile(item_path):
                files.append(item)
    except FileNotFoundError:
        print(f"Error: Directory '{path}' not found.")
        return []
    except PermissionError:
        print(f"Error: Permission denied to access '{path}'.")
        return []
    except Exception as e:
        print(f"An unexpected error occurred while listing files in '{path}': {e}")
        return []
    return files

def get_subdirectories_os(path):
    subdirectories = []
    try:
        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            if os.path.isdir(item_path):
                subdirectories.append(item)
    except FileNotFoundError:
        print(f"Error: Directory '{path}' not found.")
    except PermissionError:
        print(f"Error: Permission denied to access '{path}'.")
    return subdirectories

#######################################
# Core functions

def get_groups(host):

    groups_file_path = os.path.join(DATA_PATH, host, 'groups')

    if not os.path.exists(groups_file_path):
        logging.error(f"Groups file not found: {groups_file_path}")
        return None
    
    with open(groups_file_path, 'r') as f:
        groups_data = f.read()

    return groups_data

def get_passwd_users(host):

    passwd_file_path = os.path.join(DATA_PATH, host, 'passwd')

    if not os.path.exists(passwd_file_path):

        logging.error(f"File not found: {passwd_file_path}")

        return None

    with open (passwd_file_path, 'r') as f:

        passwd_data = f.read()
    
    return passwd_data

def load_groups_from_groups_file(app, groups_data):

    host_name = app.name

    for row in groups_data.splitlines():

        fields = row.split(':')

        if len(fields) < GROUP_FILE_FIELD_COUNT:
            logging.warning(f"Malformed line in groups file: {host_name}: {row}")
            continue

        group_name = fields[0]
        group_members = fields[3].split(',') if fields[3] else []

        app.add_local_group(group_name)

        for member in group_members:
            if member in app.local_users:
                app.local_users[member].add_group(group_name)

def load_sudoers_from_sudoers_file(app, path):

    sobj = Sudoers(path=path)

    for key in sobj.user_aliases:

        role_name = key

        if role_name not in app.local_roles:

            app.add_local_role(role_name, ["access"])
        
        for user in sobj.user_aliases[key]:

            if user not in app.local_users:

                app.add_local_user(user)
            
            app.local_users[user].add_role(role_name, apply_to_application=True)

    for rule in sobj.rules:

        users = rule['users']

        for user in users:

            user_or_group = 'user'

            if user[0] == '%':

                user_or_group = 'group'

                a = user.split('%')

                group_name = a[1]
            
            for command_detail in rule['commands']:

                run_as = command_detail['run_as']

                command = command_detail['command']

                if command == 'ALL':

                    if run_as[0] == 'ALL' and run_as[1] == 'ALL':

                        # root privilege

                        if user_or_group == 'user':

                            app.local_users[user].add_role("root", apply_to_application=True)
                        
                        else:

                            app.local_groups[group_name].add_role("root", apply_to_application=True)
                        
                        continue

def load_sudoers_from_sudoers_files(app, host):

    main_sudoers_path = os.path.join(DATA_PATH, host, 'sudoers')

    if not os.path.exists(main_sudoers_path):
        logging.warning(f"main sudoers file not found: {main_sudoers_path}")
    
    load_sudoers_from_sudoers_file(app, main_sudoers_path)

    sudoers_dir_path = os.path.join(DATA_PATH, host, 'sudoers.d')

    if not os.path.exists(sudoers_dir_path):
        logging.warning(f"sudoers directory not found: {sudoers_dir_path}")

        return
    
    files = get_files_os(sudoers_dir_path)

    for filename in files:

        path = os.path.join(sudoers_dir_path, filename)

        load_sudoers_from_sudoers_file(app, path)

    return

def load_users_from_passwd_file(app, passwd_data):

    host_name = app.name

    for row in passwd_data.splitlines():

        fields = row.split(':')

        if len(fields) != PASSWD_FILE_FIELD_COUNT:

            logging.warning(f"Malformed line in passwd file: {app.name}: {row}")
            continue

        username = fields[0]
        userid = fields[2]
        primary_group_id = fields[3]
        full_name = fields[4]
        home_dir = fields[5]
        shell = fields[6]

        if username.lower() in USERNAMES_TO_IGNORE_LOWER:
            logging.info(f"skipping user {username} in {host_name}")
            continue

        if username in app.local_users: # this should never happen, but just in case
            logging.error(f"Duplicate username {username} found in {host_name}")
            exit()

        app.add_local_user(name=username)

def parse_auth_log(log):
    """
    Parses authentication logs and extracts successful SSH login attempts.
    Supports multiple timestamp formats for different distributions.
    """
    logins = []

    # Define multiple regex patterns for different timestamp formats
    timestamp_patterns = [
        # 1. ISO 8601 Timestamp (Modern)
        re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+\+\d+:\d+ .*sshd\[\d+\]: Accepted (\w+) for (\S+) from ([\d\.]+) port (\d+)"),
        
        # 2. Traditional Syslog Timestamp (Month Day HH:MM:SS)
        re.compile(r"(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) .*sshd\[\d+\]: Accepted (\w+) for (\S+) from ([\d\.]+) port (\d+)")
    ]

    for line in log.splitlines():
        for pattern in timestamp_patterns:
            match = pattern.search(line)
            if match:
                timestamp, auth_method, user, ip, port = match.groups()
                logins.append({
                    "timestamp": timestamp,
                    "user": user,
                    "ip": ip,
                    "auth_method": auth_method,
                    "port": port
                })
                break  # Stop checking once a match is found

    logins.sort(key=lambda x: x["timestamp"], reverse=True)  # Sort newest first

    return logins

def parse_auth_logs(app, host):

    logs_path = os.path.join(DATA_PATH, host, 'logs')
    
    files = get_files_os(logs_path)

    for filename in files:

        path = os.path.join(logs_path, filename)

        print(path)

        with open(path, 'r') as f:
            log = f.read()

        log_dict = parse_auth_log(log)

        parse_logins(app, log_dict)

    return

def parse_logins(app, logins):

    for login in logins:

        username = login["user"]

        if username not in app.local_users:

            user = app.add_local_user(username)

            user.set_property("in_directory", False)
        
        else:

            user = app.local_users[username]

        formatted_timestamp = format_rfc3339(login["timestamp"])

        user.last_login_at = formatted_timestamp

#######################################
# Veza SDK utility functions

def check_provider(veza_con, PROVIDER_NAME, template_type):

    log.info(f'checking veza to see if provider (application type) "{PROVIDER_NAME}" exists...')

    if not veza_con.get_provider(PROVIDER_NAME):
        log.info(f'provider {PROVIDER_NAME} not found, creating...')
        veza_con.create_provider(PROVIDER_NAME, template_type)
        log.info(f'created provider {PROVIDER_NAME}')
    else:
        log.info(f'found provider {PROVIDER_NAME}')
    
    log.info("-------------------------------")

def dump_json(app):

    payload = app.get_payload()

    with open('payload.json', 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

def get_app(name):
    """
    Creates a CustomApplication instance with the given name and type.
    """
    app = CustomApplication(name=f'{name}', application_type=PROVIDER_NAME)

    app.add_custom_permission("access", [OAAPermission.Uncategorized])

    app.add_custom_permission("admin", [OAAPermission.Uncategorized])

    app.add_custom_permission("root", [OAAPermission.Uncategorized])

    app.add_local_role("root", ["root"])

    app.property_definitions.define_local_user_property(name="in_directory", property_type=OAAPropertyType.BOOLEAN)

    return app

def get_veza_client():

    VEZA_API_KEY = os.getenv('VEZA_API_KEY')
    VEZA_URL = os.getenv('VEZA_URL')

    if not (VEZA_URL or VEZA_API_KEY):
        log.error("Must set VEZA_URL and VEZA_API_KEY")
        sys.exit(1)

    try:
        log.info("Testing Veza credentials...")
        veza_con = OAAClient(url=VEZA_URL, api_key=VEZA_API_KEY)
    except OAAClientError as e:
        log.error("Unable to connect to Veza API")
        log.error(e)
        sys.exit(1)
    
    log.info('Connected to Veza successfully')
    log.info(f'Veza tenant: {VEZA_URL}')
    log.info('-------------------------------')

    return veza_con

def push_app(veza_con, app, data_source_name):

    # data_source_name = app.name

    print(f'the data source name is: {data_source_name}')

    try:
        response = veza_con.push_application(PROVIDER_NAME,
                                            data_source_name=data_source_name,
                                            application_object=app,
                                            save_json=SAVE_JSON
                                            )
        if response.get("warnings", None):
            print("-- Push succeeded with warnings:")
            for e in response["warnings"]:
                print(f"  - {e}")
        else:
            print("-- Push succeeded!")
    except OAAClientError as e:
        print(f"-- Error: {e.error}: {e.message} ({e.status_code})", file=sys.stderr)
        if hasattr(e, "details"):
            for d in e.details:
                print(f"  -- {d}", file=sys.stderr)

#######################################

def main():

    # get a veza sdk client
    veza_con = get_veza_client()

    # check to make sure that the provider exists in veza
    check_provider(veza_con, PROVIDER_NAME, "application")

    #########################################

    dirs = get_subdirectories_os(DATA_PATH)

    for host_name in dirs:

        log.info(f"Found subdirectory (host): {host_name}")

        app = get_app(host_name)

        #########################################
        # parse passwd file

        passwd_users = get_passwd_users(host_name)

        if not passwd_users:
            continue

        load_users_from_passwd_file(app, passwd_users)

        #########################################
        # parse groups file

        groups = get_groups(host_name)

        if not groups:
            continue

        load_groups_from_groups_file(app, groups)

        #########################################
        # parse auth log files

        parse_auth_logs(app, host_name)

        #########################################
        # parse sudoers files

        load_sudoers_from_sudoers_files(app, host_name)

        #########################################

        dump_json(app)

        ###################################
        # push app to Veza
        ###################################

        push_app(veza_con, app, host_name)

    exit()

if __name__ == "__main__":
    main()
