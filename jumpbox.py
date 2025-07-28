#!env python3

import json
import logging
import os
import paramiko
import re
import sys

from datetime import datetime, timezone
from dotenv import load_dotenv
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import OAAPropertyType, CustomApplication, OAAPermission

from paramiko import SSHConfig

########################################
# SSH config

with open("config.json", "r") as file:
    config = json.load(file)

IGNORE_HOSTS    = config['IGNORE_HOSTS']
IGNORE_USERS    = config['IGNORE_USERS']
MAX_LOGS        = config['MAX_LOGS']
SSH_CONFIG_PATH = config['SSH_CONFIG_PATH']

#######################################
# Veza config

load_dotenv()

APPLICATION_TYPE = os.getenv('APPLICATION_TYPE')
VEZA_API_KEY = os.getenv('VEZA_API_KEY')
VEZA_URL = os.getenv('VEZA_URL')

SAVE_JSON = True

########################################
# Read the SSH config file
with open(SSH_CONFIG_PATH) as file:
    ssh_config = SSHConfig()
    ssh_config.parse(file)

# logging.basicConfig(level=logging.DEBUG)

logging.basicConfig(level=logging.INFO)

log = logging.getLogger()

########################################

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

def get_hosts():
    hosts = {}

    for entry in ssh_config._config:
        host_label = entry["host"][0]  # Extract the host label
        host_entry = ssh_config.lookup(host_label)  # Get host details

        if host_entry.get("hostname") in IGNORE_HOSTS:
            continue  # Skip ignored hosts

        # Remove 'identityagent' if present
        host_entry.pop("identityagent", None)

        hosts[host_label] = host_entry  # Store in dictionary with host_label as key

    return hosts  # Return the dictionary

def get_groups(host, host_label):
    """
    Retrieves only groups that contain at least one user who can SSH into the system.
    """
    hostname = host.get("hostname", "default_host")
    ssh = get_ssh_client(host, host_label)

    try:
        # Fetch all groups and users
        stdin, stdout, stderr = ssh.exec_command("getent group")
        group_output = stdout.read().decode().strip()

        stdin, stdout, stderr = ssh.exec_command("getent passwd")
        passwd_output = stdout.read().decode().strip()

        error_output = stderr.read().decode().strip()
        if error_output:
            print(f"Error retrieving groups on {hostname}: {error_output}")
            return {}

        # Get the list of users who can SSH
        ssh_users = set(get_users(host, host_label).keys())  # Extract usernames

        groups = {}

        # Parse secondary groups from getent group
        for line in group_output.splitlines():
            parts = line.split(":")
            if len(parts) < 4:
                continue

            group_name = parts[0]
            group_members = set(parts[3].split(",")) if parts[3] else set()

            # Only add the group if it has at least one SSH-enabled user
            if group_members & ssh_users:
                groups[group_name] = group_members

        # Parse primary groups from getent passwd
        for line in passwd_output.splitlines():
            parts = line.split(":")
            if len(parts) < 4:
                continue

            username = parts[0]
            primary_gid = parts[3]

            if username in ssh_users:  # Ensure only SSH users are considered
                for group_name, members in groups.items():
                    if primary_gid in parts:
                        members.add(username)  # Add SSH-enabled user to primary group

        # Convert sets back to lists
        for group_name in groups:
            groups[group_name] = list(groups[group_name])

        return groups

    except paramiko.ssh_exception.SSHException as e:
        print(f"SSH error on {hostname}: {e}")
    except Exception as e:
        print(f"General error on {hostname}: {e}")
    finally:
        ssh.close()
        print(f"Connection to {hostname} closed.")

    return {}

def get_password(hostname):

    return os.getenv(hostname)

def get_ssh_client(host, host_label):
    """
    Creates and returns an SSH client connected to the specified host.
    """
    hostname = host.get("hostname", "default_host")
    username = host.get("user", "default_user")
    key_file = host.get("identityfile", [None])[0]
    password_auth = host.get("preferredauthentications") == "password"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"Connecting to {hostname} as {username}...")

        if password_auth:

            password = get_password(host_label)

            ssh.connect(hostname=hostname, username=username, password=password)
        else:
            ssh.connect(hostname=hostname, username=username, key_filename=key_file)

        return ssh

    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname}. Check credentials.")
    except paramiko.SSHException as e:
        print(f"SSH error on {hostname}: {e}")
    except Exception as e:
        print(f"General error on {hostname}: {e}")

    return None

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

def get_sudo_status(host, host_label, users):

    for username, user in users.items():

        user['can_sudo'] = has_sudo_privileges(host, host_label, username)

def has_sudo_privileges(host, host_label, target_user):

    hostname = host.get("hostname", "default_host")

    ssh = get_ssh_client(host, host_label)

    try:
        # Run sudo -l -U to check sudo privileges for the target user
        command = f"sudo -l -U {target_user} 2>/dev/null"
        stdin, stdout, stderr = ssh.exec_command(command)

        sudo_output = stdout.read().decode().strip()
        error_output = stderr.read().decode().strip()

        if error_output:
            print(f"Error checking sudo privileges for {target_user} on {hostname}: {error_output}")
            return False

        has_sudo = "may run the following commands" in sudo_output

        return has_sudo

    except paramiko.ssh_exception.SSHException as e:
        print(f"SSH error on {hostname}: {e}")
    except Exception as e:
        print(f"General error on {hostname}: {e}")
    finally:
        ssh.close()
        print(f"Connection to {hostname} closed.")

    return False

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

#######################################

def main():

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
