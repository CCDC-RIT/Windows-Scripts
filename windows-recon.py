# IMPORTANT NEEDS TO BE ENABLED ON ALL BOXES!!!
#https://community.fortinet.com/t5/FortiSOAR-Knowledge-Base/Troubleshooting-Tip-Exchange-Microsoft-WinRM-Connector-Error/ta-p/324015

# Windows Reconnaissance Script to Fill Out Ansible Inventory
import os
import nmap
import winrm
import argparse
import paramiko
import socket

# Global Variables
#ANSIBLE_INVENTORY_FILE = '/Windows-Scripts/ansible/inventory/inventory.yml'
ANSIBLE_INVENTORY_FILE = '/Windows-Scripts/test_inventory.yml' # Used for testing without destroying actual inventory
IP_FILE = '/opt/passwordmanager/windows_starting_clients.txt'
LOG_FOLDER = '/Windows-Scripts/recon_logs/'
GENERAL_LOG_FILE = '/Windows-Scripts/recon_logs/general_log.txt'
global SUBNET
global DOMAIN_CREDENTIALS
global LINUX_CREDENTIALS

global SCRIPTS_PATH

global PASSWORD_MANAGER_IP
global GRAFANA_IP

global HOST_INFO

global LOCAL_IP

# Scans the given subnet for hosts
def scan_all_hosts(subnet):
    global HOST_INFO

    nm = nmap.PortScanner()
    # for testing
    subnet = "192.168.1.33,192.168.1.35,192.168.1.36"
    # param gets passed as comma separated, nmap wants spaces
    subnet = subnet.replace(',', ' ')
    nm.scan(hosts=subnet, arguments='-O -p 22,3389,5985,5986')
    for host in [x for x in nm.all_hosts()]:
        os_version = determine_os(nm, host)
        if os_version == "Windows":
            print(f"Windows Host {host} detected:\n",end="")
            create_log_file(host)
            log(f'{LOG_FOLDER}/{host}.txt', f"Found Windows Host: {host}")
            # determine_os_version
        else:
            print(f"Unix Host {host} detected:\n",end="")
            create_log_file(host)
            log(f'{LOG_FOLDER}/{host}.txt', f"Found Unix Host: {host}")
            if GRAFANA_IP is None:
                find_grafana(host)

        lport = nm[host]['tcp'].keys()

        HOST_INFO[host] = {
            'OS': os_version,
            'OS_Version': '',
            'Username': None,
            'Password': None,
            'Services': set(),
        }

        for port in lport:
            log(f'{LOG_FOLDER}/{host}.txt', 'port : %s\tstate : %s' % (port, nm[host]['tcp'][port]['state']))
            if port == 22 and nm[host]['tcp'][port]['state'] == 'open':
                HOST_INFO[host]['Services'].add('SSH')
                print("SSH ", end="")
            elif port == 3389 and nm[host]['tcp'][port]['state'] == 'open':
                HOST_INFO[host]['Services'].add('RDP')
                print("RDP ", end="")
            elif port == 5985 and nm[host]['tcp'][port]['state'] == 'open':
                HOST_INFO[host]['Services'].add('WinRM_HTTP')
                print("WinRM_HTTP ", end="")
            elif port == 5986 and nm[host]['tcp'][port]['state'] == 'open':
                HOST_INFO[host]['Services'].add('WinRM_HTTPS')
                print("WinRM_HTTPS ", end="")
        
        print("")
        print("")
        log(f'{LOG_FOLDER}/{host}.txt', "")
            
    return nm

def find_grafana(host):
    global GRAFANA_IP
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments='-p 3000')
    if nm[host].has_tcp(3000) and nm[host]['tcp'][3000]['state'] == 'open':
        GRAFANA_IP = host
        print(f"Set as Grafana IP\n",end="")

# Attempts to gather additional information about Windows hosts
def gather_info(original_scan):
    global HOST_INFO
    command_output = {}
    
    for host in HOST_INFO.keys():
        os_version = determine_os(original_scan, host)
        if os_version == "Windows":
            if 'WinRM_HTTP' in HOST_INFO[host]['Services'] or 'WinRM_HTTPS' in HOST_INFO[host]['Services']:
                log(f'{LOG_FOLDER}/{host}.txt', f"Attempting WinRM HTTP connection to {host}")
                for i in range(len(DOMAIN_CREDENTIALS)):
                    username = DOMAIN_CREDENTIALS[i][0]
                    password = DOMAIN_CREDENTIALS[i][1]
                    try:
                        session = winrm.Session(
                            host,
                            auth=(f"{username}", password),
                            server_cert_validation='ignore',
                            transport='ntlm'
                        )
                        HOST_INFO[host]['Username'] = username
                        HOST_INFO[host]['Password'] = password
                        print(f"Windows Host {host}:")
                        print(f"Credentials: {username}:{password}")
                        detect_scored_services(session, host)
                        determine_windows_os_version(session, host)
                        log(IP_FILE, host)
                        continue
                    except Exception as e:
                        pass
                        print(e)
                        # print(f"Windows Host {host} Failed WinRM Scan, Running Port Scan:\n",end="")
                if HOST_INFO[host]['Username'] is None or HOST_INFO[host]['Password'] is None:
                    print(f"Windows Host {host} WinRM Authentication Failed, Running Port Scan:\n",end="")
                    port_scan_only(host, command_output)
            else:
                print(f"Windows Host {host} has WinRM Disabled, Running Port Scan:\n",end="")
                port_scan_only(host, command_output)
        else:
            print(f"Unix Host {host} Port Scan:\n",end="")
            port_scan_only(host, command_output)
            if HOST_INFO[host]['OS'] == 'Linux' and LINUX_CREDENTIALS is not None:
                determine_unix_os_version(host)
            else:
                print("")
        
    return command_output

# Determines scored service via WinRM
def detect_scored_services(session, ip_address):
    global HOST_INFO

    log_file = f'{LOG_FOLDER}/{ip_address}.txt'
    print("Detected Potential Scored Services: ",end="")
    check_ftp = session.run_cmd('sc query ftpsvc')
    if check_ftp.status_code != 0:
        log(log_file, "FTP service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":21"').std_out.decode() == '':
            log(log_file, "FTP service is not running.")
        else:
            print("FTP:21 ",end="")
            log(log_file, "FTP is Present")
            log(log_file, check_ftp.std_out.decode())
            HOST_INFO[ip_address]['Services'].add('FTP')

    check_ssh = session.run_cmd('sc query sshd')
    if check_ssh.status_code != 0:
        log(log_file, "SSH service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":22"').std_out.decode() == '':
            log(log_file, "SSH service is not running.")
        else:
            print("SSH:22 ")
            log(log_file, "SSH is Present")
            log(log_file, check_ssh.std_out.decode())
            HOST_INFO[ip_address]['Services'].add('SSH')

    check_telnet = session.run_cmd('sc query telnet')
    if check_telnet.status_code != 0:
        log(log_file, "Telnet service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":23"').std_out.decode() == '':
            log(log_file, "Telnet service is not running.")
        else:
            print("Telnet:23 ",end="")
            log(log_file, "Telnet is Present")
            log(log_file, check_telnet.std_out.decode())
            HOST_INFO[ip_address]['Services'].add('Telnet')

    check_dns = session.run_cmd('sc query dns')
    if check_dns.status_code != 0:
        log(log_file, "DNS service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":53"').std_out.decode() == '':
            log(log_file, "DNS service is not running.")
        else:
            print("DNS:53 ",end="")
            log(log_file, "DNS is Present")
            log(log_file, check_dns.std_out.decode())
            HOST_INFO[ip_address]['Services'].add('DNS')

    check_dhcp = session.run_cmd('sc query dhcpserver')
    if check_dhcp.status_code != 0:
        log(log_file, "DHCP service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":67"').std_out.decode() == '':
            log(log_file, "DHCP service is not running.")
        else:
            print("DHCP:67 ",end="")
            log(log_file, "DHCP is Present")
            log(log_file, check_dhcp.std_out.decode())
            HOST_INFO[ip_address]['Services'].add('DHCP')

    check_http_iis = session.run_cmd('sc query w3svc')
    if check_http_iis.status_code != 0:
        log(log_file, "HTTP_IIS service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":80"').std_out.decode() == '':
            log(log_file, "HTTP_IIS service is not running.")
        else:
            print("HTTP_IIS:80 ",end="")
            log(log_file, "HTTP_IIS is Present")
            log(log_file, check_http_iis.std_out.decode())
            HOST_INFO[ip_address]['Services'].add('HTTP')
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":443"').std_out.decode() != '':
            print("HTTPS_IIS:443 ",end="")
            log(log_file, "HTTPS_IIS is Present")
            log(log_file, check_http_iis.std_out.decode())
            HOST_INFO[ip_address]['Services'].add('HTTPS')
    check_http_nginx = session.run_cmd('sc query nginx')
    if check_http_nginx.status_code != 0:
        log(log_file, "HTTP_Nginx service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":80"').std_out.decode() == '':
            log(log_file, "HTTP_Nginx service is not running.")
        else:
            print("HTTP_Nginx:80 ",end="")
            log(log_file, "HTTP_Nginx is Present")
            log(log_file, check_http_nginx.std_out.decode())
            HOST_INFO[ip_address]['Services'].add('HTTP')
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":443"').std_out.decode() != '':
            print("HTTPS_Nginx:443 ",end="")
            log(log_file, "HTTPS_Nginx is Present")
            log(log_file, check_http_nginx.std_out.decode())
            HOST_INFO[ip_address]['Services'].add('HTTPS')

    check_http_apache = session.run_cmd('sc query Apache2.4')
    if check_http_apache.status_code != 0:
        check_http_apache = session.run_cmd('sc query Apache24')
        if check_http_apache.status_code != 0:
            check_http_apache = session.run_cmd('sc query Apache')
            if check_http_apache.status_code != 0:
                log(log_file, "HTTP_Apache service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":80"').std_out.decode() == '':
            log(log_file, "HTTP_Apache service is not running.")
        else:
            print("HTTP_Apache:80 ",end="")
            log(log_file, "HTTP_Apache is Present")
            log(log_file, check_http_apache.std_out.decode())
            HOST_INFO[ip_address]['Services'].add('HTTP')
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":443"').std_out.decode() != '':
            print("HTTPS_Apache:443 ",end="")
            log(log_file, "HTTPS_Apache is Present")
            log(log_file, check_http_apache.std_out.decode())
            HOST_INFO[ip_address]['Services'].add('HTTPS')

    check_ntp = session.run_cmd('sc query w32time')
    if check_ntp.status_code != 0:
        log(log_file, "NTP service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":123"').std_out.decode() == '':
            log(log_file, "NTP service is not running.")
        else:
            print("NTP:123 ",end="")
            log(log_file, "NTP is Present")
            log(log_file, check_ntp.std_out.decode())
            HOST_INFO[ip_address]['Services'].add('NTP')

    check_ldap = session.run_cmd('sc query ntds')
    if check_ldap.status_code != 0:
        log(log_file, "LDAP service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":389"').std_out.decode() == '':
            log(log_file, "LDAP service is not running.")
        else:
            print("LDAP:389 ", end="")
            log(log_file, "LDAP is Present")
            log(log_file, check_ldap.std_out.decode())
            HOST_INFO[ip_address]['Services'].add('LDAP')

    check_adfs = session.run_cmd('sc query adfssrv')
    if check_adfs.status_code != 0:
        log(log_file, "ADFS service not found.")
    else:
        print("ADFS ",end="")
        log(log_file, "ADFS is Present")
        log(log_file, check_adfs.std_out.decode())
        HOST_INFO[ip_address]['Services'].add('ADFS')

    check_ca = session.run_cmd('sc query certsvc')
    if check_ca.status_code != 0:
        log(log_file, "Certificate Authority service not found.")
    else:
        print("CA ",end="")
        log(log_file, "Certificate Authority is Present")
        log(log_file, check_ca.std_out.decode())
        HOST_INFO[ip_address]['Services'].add('CA')

    check_smb = session.run_cmd('sc query lanmanserver')
    if check_smb.status_code != 0:
        log(log_file, "SMB service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":445"').std_out.decode() == '':
            log(log_file, "SMB service is not running.")
        else:
            print("SMB:445 ",end="")
            log(log_file, "SMB is Present")
            log(log_file, check_smb.std_out.decode())
            HOST_INFO[ip_address]['Services'].add('SMB')

    check_rdp = session.run_cmd('sc query termservice')
    if check_rdp.status_code != 0:
        log(log_file, "RDP service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":3389"').std_out.decode() == '':
            log(log_file, "RDP service is not running.")
        else:
            print("RDP:3389",end="")
            log(log_file, "RDP is Present")
            log(log_file, check_rdp.std_out.decode())
            HOST_INFO[ip_address]['Services'].add('RDP')
    print("\n",end="")
            

def determine_os(nm, host):
    # Check OS detection results
    os_match = nm[host].get('osmatch', [])
    
    if os_match:
        # Check all matches for Windows first (higher priority)
        for os_info in os_match:
            #print(os_info) Debugging line
            if 'Windows' in os_info.get('name', ''):
                return 'Windows'
        
        # If no Windows match found, check for Linux/Unix
        for os_info in os_match:
            if 'Linux' in os_info.get('name', ''):
                return 'Linux'
            
    return 'FreeBSD'  # Default to FreeBSD if no matches found

def determine_windows_os_version(session, ip_address):
    global HOST_INFO
    log_file = f'{LOG_FOLDER}/{ip_address}.txt'
    check_os_type = session.run_cmd('powershell -c Get-ItemPropertyValue \'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\' InstallationType')
    check_os_version = session.run_cmd('powershell -c Get-ItemPropertyValue \'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\' ProductName')
    if check_os_type.std_out.decode() != '' and check_os_version.std_out.decode() != '':
        print(f"Detected OS: {check_os_version.std_out.decode().strip()} ({check_os_type.std_out.decode().strip()})\n",end="")
        HOST_INFO[ip_address]['OS_Version'] = f"{check_os_version.std_out.decode().strip()} ({check_os_type.std_out.decode().strip()})"
    else:
        if check_os_type.std_out.decode() == '':
            log(log_file, f"Could not determine OS type for {ip_address}\n")
            print("Could not determine OS Type\n",end="")
        else:
            log(log_file, f"OS Type for {ip_address}: {check_os_type.std_out.decode().strip()}\n")
            print(f"Detected OS Type: {check_os_type.std_out.decode().strip()}",end="")
            HOST_INFO[ip_address]['OS_Version'] = f"{check_os_type.std_out.decode().strip()}"
        if check_os_version.std_out.decode() == '':
            log(log_file, f"Could not determine OS version for {ip_address}\n")
            print("Could not determine OS Version\n",end="")
        else:
            log(log_file, f"OS Version for {ip_address}: {check_os_version.std_out.decode().strip()}\n")
            print(f"Detected OS Version: {check_os_version.std_out.decode().strip()}",end="")
            HOST_INFO[ip_address]['OS_Version'] += f" {check_os_version.std_out.decode().strip()}"
    print("")

def determine_unix_os_version(ip_address):
    global HOST_INFO

    log_file = f'{LOG_FOLDER}/{ip_address}.txt'
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    username = LINUX_CREDENTIALS[0]
    password = LINUX_CREDENTIALS[1]
    try:
        ssh_client.connect(ip_address, username=username, password=password, timeout=10)
        stdin, stdout, stderr = ssh_client.exec_command('cat /etc/os-release | grep PRETTY_NAME | cut -d "=" -f2 | tr -d \'"\'')
        os_info = stdout.read().decode().strip()
        if os_info == '':
            stdin, stdout, stderr = ssh_client.exec_command('freebsd-version')
            os_info = "FreeBSD " + stdout.read().decode().strip()
        print(f"Detected OS: {os_info}\n",end="")
        HOST_INFO[ip_address]['OS_Version'] = os_info
        log(log_file, f"OS Information for {ip_address}:\n{os_info}\n")
        if "Ubuntu" in os_info:
            global PASSWORD_MANAGER_IP
            if PASSWORD_MANAGER_IP is None:
                PASSWORD_MANAGER_IP = ip_address
                print(f"Set as Password Manager IP\n",end="")
        if "FreeBSD" in os_info:
            print(f"Router Detected\n",end="")
        ssh_client.close()
    except Exception as e:
        log(log_file, f"Could not determine OS for {ip_address}\n")
        print(f"Could not determine OS for {ip_address}\n",end="")
    print("")

def log(file, content):
    with open(file, 'a') as log_file:
        log_file.write(content + '\n')

def create_log_file(host):
    log_file = f'{LOG_FOLDER}{host}.txt'
    if not os.path.exists(log_file):
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        print(f"Log file created: {log_file}")
    with open(log_file, 'w') as file:
        file.write(f'{host} Reconnaissance Log:' + '\n')

def port_scan_only(host, command_output):
    global HOST_INFO

    log_file = f'{LOG_FOLDER}/{host}.txt'
    print("Detected Potential Scored Services: ",end="")
    log(log_file, f"Could not connect to {host} via WinRM, downgrading to Port Scanning only.")
    try:
        ps = nmap.PortScanner()
        ps.scan(hosts=host, arguments='-sV -p 21,22,23,53,67,80,123,389,443,445,1500,3389,5985,5986')
        port_dict = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            53: "DNS",
            67: "DHCP",
            80: "HTTP",
            123: "NTP",
            389: "LDAP",
            443: "HTTPS",
            445: "SMB",
            1500: "ADFS",
            3389: "RDP",
            5985: "WinRM HTTP",
            5986: "WinRM HTTPS"
        }
        lport = ps[host]['tcp'].keys()
        
        # Log open ports found
        for port in lport:
            port_state = ps[host]['tcp'][port]['state']
            if port_state == 'open':
                service = port_dict.get(port, f"Unknown ({port})")
                log(log_file, f"{host}:{port} ({service}) is {port_state}")
                print(f"{service}:{port} ",end="")
                HOST_INFO[host]['Services'].add(service)
                if host not in command_output:
                    command_output[host] = f"Open ports: {port} ({service})"
                else:
                    command_output[host] += f", {port} ({service})"
        print("\n",end="")
    except Exception as e:
        print(f"Port scan failed: {str(e)}\n",end="")
        log(log_file, f"Port scan failed for {host}: {str(e)}")

def get_local_ip():
    global LOCAL_IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    LOCAL_IP = s.getsockname()[0]
    s.close()

# Adds information about Windows hosts to the Ansible inventory file
def add_to_ansible_inventory():
    global HOST_INFO

    print(f"Adding hosts to Ansible inventory file: {ANSIBLE_INVENTORY_FILE}\n")

    adfs_backup_password = os.urandom(12).hex()

    ansible_header_content = f"""---
all:
children:
  windows:
    vars:
      ansible_connection: winrm
      ansible_winrm_server_cert_validation: ignore
      ansible_winrm_port: 5985
      ansible_winrm_transport: ntlm
      scripts_path: "{SCRIPTS_PATH}"
      scripts_ansible_location: "/Windows-Scripts"
      password_manager_ip: "{PASSWORD_MANAGER_IP if PASSWORD_MANAGER_IP is not None else ''}"{' #REPLACE' if PASSWORD_MANAGER_IP is None else ''}
      grafana_ip: "{GRAFANA_IP if GRAFANA_IP is not None else ''}"{' #REPLACE' if GRAFANA_IP is None else ''}"
      adfs_backup_password: "{adfs_backup_password}"
      stabvest_ip: "{LOCAL_IP if LOCAL_IP is not None else ''}"{' #REPLACE' if LOCAL_IP is None else ''}"
      winrm_ip: "{LOCAL_IP if LOCAL_IP is not None else ''}"{' #REPLACE' if LOCAL_IP is None else ''}"
    children:
      """

    for host in HOST_INFO.keys():
        server_type = "none"
        if 'ADFS ' in HOST_INFO[host]['Services']:
            server_type = "adfs"
        elif 'SMB' in HOST_INFO[host]['Services'] and 'LDAP' in HOST_INFO[host]['Services']:
            server_type = "dc"
        elif 'CA' in HOST_INFO[host]['Services']:
            server_type = "ca"

        scored_services = HOST_INFO[host]['Services']
        scored_services.remove('WinRM_HTTP') if 'WinRM_HTTP' in scored_services else None
        scored_services.remove('WinRM_HTTPS') if 'WinRM_HTTPS' in scored_services else None
        scored_services.remove('RDP') if 'RDP' in scored_services else None
        scored_services.remove('SMB') if 'SMB' in scored_services else None
        scored_services.remove('SSH') if 'SSH' in scored_services else None
        scored_services.remove('FTP') if 'FTP' in scored_services else None
        scored_services.remove('Telnet') if 'Telnet' in scored_services else None
        scored_services.add('HTTP') if 'CA' in HOST_INFO[host]['Services'] or 'ADFS' in HOST_INFO[host]['Services'] else None
        scored_services.remove('ADFS') if 'ADFS' in scored_services else None
        scored_services.remove('CA') if 'CA' in scored_services else None    
        
        scored_services = "io, ".join(scored_services)
        if scored_services != "":
            scored_services += "io"
        else:
            scored_services = "None"
        scored_services = scored_services.lower()

        is_win_server = 'Windows Server' in HOST_INFO[host]['OS_Version']
        is_server_core = "Server Core" in HOST_INFO[host]['OS_Version']

        
        if 'SMB' in HOST_INFO[host]['Services'] and 'LDAP' in HOST_INFO[host]['Services']:
            server_type = "dc"
        elif 'CA' in HOST_INFO[host]['Services']:
            server_type = "ca"

        if HOST_INFO[host]['OS'] == 'Windows':
            ansible_header_content += f"""{host}:
        ansible_host: {host}
        ansible_user: "{HOST_INFO[host]['Username'] if HOST_INFO[host]['Username'] is not None else ''}{' #REPLACE' if HOST_INFO[host]['Username'] is None else ''}"
        ansible_password: "{HOST_INFO[host]['Password'] if HOST_INFO[host]['Password'] is not None else ''}{' #REPLACE' if HOST_INFO[host]['Password'] is None else ''}"
        scored_services: "{scored_services}"
        is_win_server: "{str(is_win_server).lower()}"
        is_server_core: "{str(is_server_core).lower()}"
        server_type: "{server_type}"
      """
    with open(ANSIBLE_INVENTORY_FILE, 'w') as inventory_file:
        inventory_file.write(ansible_header_content)

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Windows Reconnaissance Script to Fill Out Ansible Inventory')
    parser.add_argument('-s', required=True, help='Subnet to scan for Windows hosts (e.g., 192.168.1.0/24)')
    parser.add_argument('-c', required=True, help='Windows Domain Credentials in the format username:password,username:password')
    parser.add_argument('-lc', required=False, help='Linux Credentials in the format username:password,username:password')
    parser.add_argument('-sp', required=True, help='Scripts Path')
    args = parser.parse_args()

    # Clear Terminal
    os.system('clear')

    print("\n=======================================GENERAL SETUP=======================================\n\n")

    # Make sure log folder is empty and exists
    if not os.path.exists(LOG_FOLDER):
        os.makedirs(os.path.dirname(LOG_FOLDER), exist_ok=True)
        print(f"Log folder created: {LOG_FOLDER}")
    else:
        for filename in os.listdir(LOG_FOLDER):
            file_path = os.path.join(LOG_FOLDER, filename)
            try:
                os.remove(file_path)
            except Exception as e:
                print(f'Failed to delete {file_path}. Reason: {e}')
        print(f"Cleaned up old logging content: {LOG_FOLDER}")
    
    # Make sure general log file exists
    if not os.path.exists(GENERAL_LOG_FILE):
        os.makedirs(os.path.dirname(GENERAL_LOG_FILE), exist_ok=True)
        print(f"General log file created: {GENERAL_LOG_FILE}")
    with open(GENERAL_LOG_FILE, 'w') as general_log_file:
        general_log_file.write('General Reconnaissance Log:' + '\n')

    # Make sure IP file exists
    if not os.path.exists(IP_FILE):
        os.makedirs(os.path.dirname(IP_FILE), exist_ok=True)
        print(f"IP file created: {IP_FILE}")
    with open(IP_FILE, 'w') as ip_file:
        ip_file.write('[INI HEADER]' + '\n')

    # Set global variables
    global SUBNET
    global DOMAIN_CREDENTIALS
    global LINUX_CREDENTIALS
    global PASSWORD_MANAGER_IP
    global GRAFANA_IP
    global SCRIPTS_PATH

    SCRIPTS_PATH = args.sp

    PASSWORD_MANAGER_IP = None
    GRAFANA_IP = None

    global HOST_INFO
    HOST_INFO = {}

    get_local_ip()

    SUBNET = args.s
    DOMAIN_CREDENTIALS = args.c.split(',')
    for i in range(len(DOMAIN_CREDENTIALS)):
        DOMAIN_CREDENTIALS[i] = DOMAIN_CREDENTIALS[i].split(':')
    LINUX_CREDENTIALS = args.lc.split(',') if args.lc is not None else None
    if LINUX_CREDENTIALS is not None:
        for i in range(len(LINUX_CREDENTIALS)):
            LINUX_CREDENTIALS[i] = LINUX_CREDENTIALS[i].split(':')
            print(f"Using Linux Credentials | Credentials: {LINUX_CREDENTIALS}\n")
    else:
        print("")

    print("\n\n======================================SUBNET SCANNING======================================\n\n")
    print(f"Scanning subnet: {SUBNET}")
    print(f"Using Windows Credentials | {DOMAIN_CREDENTIALS}\n")
    log(GENERAL_LOG_FILE, f"Scanning subnet: {SUBNET} with credentials: {DOMAIN_CREDENTIALS}\n")

    original_scan = scan_all_hosts(SUBNET)
    print("\n============================DETECTING OS AND POTENTIAL SERVICES============================\n\n")
    gather_info(original_scan)
    print("\n==========================ADDING INFORMATION TO ANSIBLE INVENTORY==========================\n\n")
    add_to_ansible_inventory()
    

if __name__ == "__main__":
    main()