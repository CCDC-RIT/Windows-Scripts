# Imports
import winrm
import re
import argparse
import os
import json

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

# Establish WinRM Session
def create_session(host, username, password):
    try:
        # Wrap IPv6 addresses in brackets
        host_addr = f"[{host}]" if ':' in host and not host.startswith('[') else host
        session = winrm.Session(
            f'http://{host_addr}:5985/wsman',
            auth=(f"{username}", password),
            server_cert_validation='ignore',
            transport='ntlm'
        )
        return session
    except Exception as e:
        return None

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

def parse_scheduled_task_output(output, file_path):
    tasks = output.split('\r\n\r\n')
    for task in tasks:
        if file_path in task:
            match = re.search(r'TaskName:\s+(.*)', task)
            if match:
                return match.group(1).strip()
    return None

def gather_information(session, host, file_path, process_name, service_name, run_key_location, scheduled_task_name):
    global ARTIFACTS
    ARTIFACTS[host] = {
        "File Path": file_path,
        "Process Name": process_name,
        "Process ID": None,
        "Service Name": service_name,
        "Run Key Location": run_key_location,
        "Scheduled Task Name": scheduled_task_name
    }

    if file_path is not None:
        ps_script = f'Test-Path -Path "{file_path}"'
        output = session.run_cmd(f'powershell -c "{ps_script}"')
        if output.status_code == 0:
            if process_name is None:
                ps_script = 'get-process | where-object { $_.path -eq \'' + file_path + '\'} | select-object name, id, path | format-table -HideTableHeaders'
                output = session.run_cmd(f'powershell -c "{ps_script}"')
                output = output.std_out.decode().strip()
                if len(output) != 0:
                    tokens = output.split()
                    if len(tokens) >= 2:
                        ARTIFACTS[host]["Process Name"] = tokens[0]
                        ARTIFACTS[host]["Process ID"] = tokens[1]
            if service_name is None:
                ps_script = 'Get-CimInstance -ClassName win32_service | where-object { $_.PathName -eq \'' +  file_path + '\'} | select-object -ExpandProperty name'
                output = session.run_cmd(f'powershell -c "{ps_script}"')
                output = output.std_out.decode().strip()
                if len(output) != 0:
                    ARTIFACTS[host]["Service Name"] = output
                elif run_key_location is None:
                    ps_script = (
                        f'Get-ItemProperty -Path \'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\';'
                        f'Get-ItemProperty -Path \'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce\';'
                        f'Get-ItemProperty -Path \'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\';'
                        f'Get-ItemProperty -Path \'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce\''
                    )
                    output = session.run_cmd(f'powershell -c "{ps_script}"')
                    tokens = output.std_out.decode().strip().split('\r\n')
                    for token in tokens:
                        if file_path in token:
                            key_location = token.split(':')[0].strip()
                            ARTIFACTS[host]["Run Key Location"] = key_location
                            break
                elif scheduled_task_name is None:
                    ps_script = "schtasks /query /fo LIST /v"
                    output = session.run_cmd(f"powershell -c {ps_script}")
                    task_name = parse_scheduled_task_output(output.std_out.decode(), file_path)
                    if task_name is not None:
                        ARTIFACTS[host]["Scheduled Task Name"] = task_name

def format_artifacts():
    json_output = json.dumps(ARTIFACTS, indent=4)
    return json_output

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
    
    # Define variables
    username = args.u
    password = args.p

    file_path = args.file_path
    process_name = args.process_name
    service_name = args.service_name
    run_key_location = args.run_key_location
    scheduled_task_name = args.scheduled_task_name

    # Clear Terminal
    os.system('clear')

    # Gets all Windows IPs
    hosts = get_ips()

    global ARTIFACTS
    ARTIFACTS = {}

    # Runs commands against all hosts
    for host in hosts:
        ARTIFACTS[host] = {}
        session = create_session(host, username, password)
        if session is not None:
            gather_information(session, host, file_path, process_name, service_name, run_key_location, scheduled_task_name)

    json_output = format_artifacts()
    print(json_output)

if __name__ == "__main__":
    main()