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

APPLICATION_TYPE = os.getenv('APPLICATION_TYPE')
VEZA_API_KEY = os.getenv('VEZA_API_KEY')
VEZA_URL = os.getenv('VEZA_URL')

SAVE_JSON = True

########################################

DATA_PATH = './data/parser'

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

def dump_json(app):

    payload = app.get_payload()

    with open('payload.json', 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

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

def get_app(name):
    """
    Creates a CustomApplication instance with the given name and type.
    """
    app = CustomApplication(name=f'{name}', application_type=APPLICATION_TYPE)

    app.add_custom_permission("ssh_access", [OAAPermission.DataRead])
    app.add_custom_permission("local_access", [OAAPermission.DataRead])

    app.property_definitions.define_local_user_property(name="can_sudo", property_type=OAAPropertyType.BOOLEAN)
    app.property_definitions.define_local_user_property(name="in_directory", property_type=OAAPropertyType.BOOLEAN)
    app.property_definitions.define_local_user_property(name="full_name", property_type=OAAPropertyType.STRING)

    return app

def get_passwd_users(host):

    passwd_file_path = os.path.join(DATA_PATH, host, 'passwd')

    if not os.path.exists(passwd_file_path):

        logging.error(f"File not found: {passwd_file_path}")

        return None

    with open (passwd_file_path, 'r') as f:

        passwd_data = f.read()
    
    return passwd_data

def get_auth_logs(host, host_label):
    """
    Connects to a remote Linux host and retrieves authentication logs.
    Handles both regular and compressed (.gz) log files.
    Limits the number of log files read to avoid excessive data retrieval.
    """

    ssh = get_ssh_client(host, host_label)
    if not ssh:
        return "Unable to connect."

    try:
        # Determine OS log file naming (Ubuntu: auth.log, RHEL: secure)
        stdin, stdout, stderr = ssh.exec_command("test -f /var/log/auth.log && echo 'auth.log' || echo 'secure'")
        log_file = stdout.read().decode().strip()

        # Find all available auth logs (sorted by modification time, newest first)
        stdin, stdout, stderr = ssh.exec_command(f"ls -1t /var/log/{log_file}* 2>/dev/null")
        log_files = stdout.read().decode().strip().split("\n")

        if not log_files:
            return "No authentication logs found."

        # **Failsafe:** Limit the number of logs to read
        log_files = log_files[:MAX_LOGS]  # Read only the latest N log files

        all_logs = []

        for log in log_files:
            if log.endswith(".gz"):
                # If the log file is compressed, use `zcat`
                stdin, stdout, stderr = ssh.exec_command(f"sudo zcat {log}")
            else:
                # Otherwise, use `cat`
                stdin, stdout, stderr = ssh.exec_command(f"sudo cat {log}")

            log_data = stdout.read().decode().strip()
            if log_data:
                all_logs.append(log_data)

        return "\n".join(all_logs)

    finally:
        ssh.close()

def get_groups(host):

    groups_file_path = os.path.join(DATA_PATH, host, 'groups')

    if not os.path.exists(groups_file_path):
        logging.error(f"Groups file not found: {groups_file_path}")
        return None
    
    with open(groups_file_path, 'r') as f:
        groups_data = f.read()

    return groups_data

def load_sudoers_from_sudoers_file(app, path):

    sobj = Sudoers(path=path)

    for rule in sobj.rules:

        print("------------")
        print(rule)

        users = rule['users']

        for user in users:

            print(user)

            user_or_group = 'user'

            if user[0] == '%':

                user_or_group = 'group'

                a = user.split('%')

                group_name = a[1]
            
            for command_detail in rule['commands']:

                print("###")
                print(command_detail['command'])

                command = command_detail['command']

                if command not in app.resources:

                    r = app.add_resource(command, command)
                
                else:

                    r = app.resources[command]
                
                if user_or_group == 'user':

                    app.local_users[user].add_permission(permission="execute", resources=[r])
                
                else:

                    app.local_groups[group_name].add_permission(permission="execute", resources=[r])

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

def get_password(hostname):

    return os.getenv(hostname)
        
def get_users(host, host_label):

    users = {}

    hostname = host.get("hostname", "default_host")

    ssh = get_ssh_client(host, host_label)

    if not ssh:
        return {}

    try:
        stdin, stdout, stderr = ssh.exec_command("getent passwd | awk -F: '$7 !~ /(nologin|false)/'")
        raw_users = stdout.read().decode().strip()
        error_output = stderr.read().decode().strip()

        if error_output:
            print(f"Error executing getent passwd on {hostname}: {error_output}")
            return {}

        print(f"Executed getent passwd on: {hostname}")
        
        for row in raw_users.splitlines():
            fields = row.split(':')

            if len(fields) < 7:
                print(f"Skipping malformed line on {hostname}: {row}")
                continue

            username = fields[0]
            userid = fields[2]
            primary_group_id = fields[3]
            full_name = fields[4]
            home_dir = fields[5]
            shell = fields[6]

            if username.lower() in IGNORE_USERS:
                continue

            users[username] = {
                "userid": userid,
                "primary_group_id": primary_group_id,
                "full_name": full_name,
                "home_dir": home_dir,
                "shell": shell,
                "in_directory": True,
                "last_login_at": None
            }

        return users

    except paramiko.ssh_exception.SSHException as e:
        print(f"SSH error on {hostname}: {e}")
    except Exception as e:
        print(f"General error on {hostname}: {e}")
    finally:
        ssh.close()
        print(f"Connection to {hostname} closed.")

    return {}

def parse_auth_logs(logs):
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

    for line in logs.splitlines():
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

def parse_logins(users, logins):

    existing_users = users.keys()

    found_users = []

    for login in logins:

        username = login["user"]

        if username not in existing_users:

            users[username] = {
                "full_name": username,
                "in_directory": False,
            }

        if username not in found_users:

            found_users.append(username)

            formatted_timestamp = format_rfc3339(login["timestamp"])

            users[username]["last_login_at"] = formatted_timestamp

#######################################
# Veza functions

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

        # app.add_local_user(name=username, unique_id=userid)
        app.add_local_user(name=username)

def load_groups_from_groups_file(app, groups_data):

    host_name = app.name

    for row in groups_data.splitlines():

        fields = row.split(':')

        if len(fields) < GROUP_FILE_FIELD_COUNT:
            logging.warning(f"Malformed line in groups file: {host_name}: {row}")
            continue

        group_name = fields[0]
        group_members = fields[3].split(',') if fields[3] else []

        print("the group name is", group_name)
        app.add_local_group(group_name)

        for member in group_members:

            print(f'the member is: {member}')
            if member in app.local_users:
                app.local_users[member].add_group(group_name)

                print(f'adding group {group_name} to {member}')

def load_users(app, users):

    for username, user_data in users.items():

        if username not in app.local_users.keys():

            user = app.add_local_user(username)
        
        else:

            user = app.local_users[username]

        user.set_property("can_sudo", user_data["can_sudo"])
        user.set_property("in_directory", user_data["in_directory"])
        user.set_property("full_name", user_data["full_name"])
        user.last_login_at = user_data["last_login_at"]

        user.add_permission("ssh_access", apply_to_application=True)

def load_groups(app, groups):

    for group_name, users in groups.items():

        app.add_local_group(group_name)

        for username in users:

            if username in app.local_users:

                app.local_users[username].add_group(group_name)

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

def main():

    dirs = get_subdirectories_os(DATA_PATH)

    for host_name in dirs:

        print(f"Found subdirectory (host): {host_name}")

        app = get_app(host_name)

        app.add_custom_permission("execute", [OAAPermission.Uncategorized])

        #########################################
        # parse passwd file

        passwd_users = get_passwd_users(host_name)

        if not passwd_users:
            continue

        load_users_from_passwd_file(app, passwd_users)

        #########################################
        # parse groups file

        print(f"the groups are:")
        groups = get_groups(host_name)

        print(groups)

        if not groups:
            continue

        load_groups_from_groups_file(app, groups)

        #########################################
        # parse sudoers files

        print("looking for sudoers...")

        load_sudoers_from_sudoers_files(app, host_name)

        #########################################

        dump_json(app)

        # print(passwd_users)

    exit()




    # Example usage:
    directory_to_scan = '.' # Current directory
    # directory_to_scan = '/path/to/your/directory' # Replace with your target directory

    authz_metadata = {}

    hosts = get_hosts()

    for host_label in hosts:

        print(host_label)

        host = ssh_config.lookup(host_label)

        log.info(f"Getting users from {host}...")

        users = get_users(host, host_label)

        log.info(f"Getting auth logs from {host}...")

        auth_logs = get_auth_logs(host, host_label)

        log.info(f"Parsing auth logs for successful logins...")

        logins = parse_auth_logs(auth_logs)

        log.info(f"Adding last_login to user records...")

        parse_logins(users, logins)

        log.info(f"Checking sudo status of users...")

        get_sudo_status(host, host_label, users)

        log.info(f"Getting groups from {host}...")

        groups = get_groups(host, host_label)

        authz_metadata[host_label] = {
            "users": users,
            "groups": groups
        }

    ###################################
    # push to Veza
    ###################################
    # test API key

    if not (VEZA_URL or VEZA_API_KEY):
        log.error("Must set VEZA_URL and VEZA_API_KEY")
        sys.exit(1)

    try:
        log.info("Testing Veza credentials")
        veza_con = OAAClient(url=VEZA_URL, api_key=VEZA_API_KEY)
    except OAAClientError as e:
        log.error("Unable to connect to Veza API")
        log.error(e)
        sys.exit(1)
    
    log.info('connected to Veza successfully')

    ###################################

    for host_label, host_data in authz_metadata.items():

        host_label = f'linux-{host_label}'

        if not veza_con.get_provider(host_label):
            log.info(f"Creating new provider {host_label}")
            veza_con.create_provider(host_label, "application")

        app = CustomApplication(name=host_label, application_type=APPLICATION_TYPE)

        # for now, we're going to just add users with a standard "access" permission
        app.add_custom_permission("ssh_access", [OAAPermission.DataRead])

        app.property_definitions.define_local_user_property(name="can_sudo", property_type=OAAPropertyType.BOOLEAN)
        app.property_definitions.define_local_user_property(name="in_directory", property_type=OAAPropertyType.BOOLEAN)
        app.property_definitions.define_local_user_property(name="full_name", property_type=OAAPropertyType.STRING)

        load_users(app, host_data["users"])

        load_groups(app, host_data["groups"])

        ###################################
        # Push the metadata payload:

        try:
            response = veza_con.push_application(host_label,
                                                data_source_name=host_label,
                                                application_object=app,
                                                save_json=SAVE_JSON
                                                )
            if response.get("warnings", None):
                print("-- Push succeeded with warnings:")
                for e in response["warnings"]:
                    print(f"  - {e}")
        except OAAClientError as e:
            print(f"-- Error: {e.error}: {e.message} ({e.status_code})", file=sys.stderr)
            if hasattr(e, "details"):
                for d in e.details:
                    print(f"  -- {d}", file=sys.stderr)

    exit()

if __name__ == "__main__":
    main()
