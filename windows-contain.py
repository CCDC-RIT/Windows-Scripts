# Imports
import winrm
import re
import argparse
import os

ALL_HOSTS = "/opt/passwordmanager/windows_starting_clients.txt"

# global FILE_PATH
# global SERVICE_NAME
# global PROCESS_NAME
# global RUN_KEY_LOCATION
# global SCHEDULED_TASK_NAME

global ARTIFACTS

# Fixes PyWinRM ipv6 issue (Shoutout illidian80 on github)
_original_build_url = winrm.Session._build_url
@staticmethod
def _patched_build_url(target, transport):
    # IPv6 pattern matching
    ipv6_match = re.match(
        r'(?i)^((?P<scheme>http[s]?)://)?(\[(?P<ipv6>[0-9a-f:]+)\])(:(?P<port>\d+))?(?P<path>(/)?(wsman)?)?',
        target
    )
    if ipv6_match:
        scheme = ipv6_match.group('scheme') or ('https' if transport == 'ssl' else 'http')
        host = '[' + ipv6_match.group('ipv6') + ']'
        port = ipv6_match.group('port') or ('5986' if transport == 'ssl' else '5985')
        path = ipv6_match.group('path') or 'wsman'
        return '{0}://{1}:{2}/{3}'.format(scheme, host, port, path.lstrip('/'))
    return _original_build_url(target, transport)
winrm.Session._build_url = _patched_build_url

# Runs commands using PyWinRM
def run_command(host, username, password):
    try:
        # Wrap IPv6 addresses in brackets
        host_addr = f"[{host}]" if ':' in host and not host.startswith('[') else host
        session = winrm.Session(
            f'http://{host_addr}:5985/wsman',
            auth=(f"{username}", password),
            server_cert_validation='ignore',
            transport='ntlm'
        )
        session.run_cmd(...)
    except Exception as e:
        pass

# Gets all IPs from the password manager file
def get_ips():
    ignore_first_line = True
    WINDOWS_HOSTS = []
    with open(ALL_HOSTS, 'r') as ip_file:
        for line in ip_file:
            if ignore_first_line:
                ignore_first_line = False
                continue
            host = line.strip()
            WINDOWS_HOSTS.append(host)
    return WINDOWS_HOSTS

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Windows Containment Script')
    parser.add_argument('-u', required=True, help='Windows Domain Admin Username')
    parser.add_argument('-p', required=True, help='Windows Domain Admin Password')
    parser.add_argument('--file-path', required=False, help='File path to contain from remote hosts')
    parser.add_argument('--process-name', required=False, help='Process name to contain from remote hosts')
    parser.add_argument('--service-name', required=False, help='Service name to contain from remote hosts')
    parser.add_argument('--run-key-location', required=False, help='Registry Run Key location to contain from remote hosts')
    parser.add_argument('--scheduled-task-name', required=False, help='Scheduled Task name to contain from remote hosts')
    args = parser.parse_args()
    
    # Set global variables
    username = args.u
    password = args.p

    # Clear Terminal
    os.system('clear')

    # Gets all Windows IPs
    hosts = get_ips()

    # Runs commands against all hosts
    for host in hosts:
        run_command(host, username, password)

if __name__ == "__main__":
    main()