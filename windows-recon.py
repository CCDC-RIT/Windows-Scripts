# IMPORTANT NEEDS TO BE ENABLED ON ALL BOXES!!!
#https://community.fortinet.com/t5/FortiSOAR-Knowledge-Base/Troubleshooting-Tip-Exchange-Microsoft-WinRM-Connector-Error/ta-p/324015

# Windows Reconnaissance Script to Fill Out Ansible Inventory
import os
import os
import nmap
import json
import winrm
import argparse

# Global Variables
ANSIBLE_INVENTORY_FILE = '/Windows-Scripts/ansible/inventory/inventory.yml'
IP_FILE = '/opt/passwordmanager/windows_starting_clients.txt'
LOG_FOLDER = '/Windows-Scripts/recon_logs/'
GENERAL_LOG_FILE = '/Windows-Scripts/recon_logs/general_log.txt'
global SUBNET
global DOMAIN_USERNAME
global DOMAIN_PASSWORD

global PASSWORD_MANAGER_IP
global GRAFANA_IP

# Scans the given subnet for hosts
def scan_all_hosts(subnet):
    found_hosts = {}
    nm = nmap.PortScanner()
    subnets = subnet.split(",")
    for subnet in subnets:
        nm.scan(hosts=subnet, arguments='-O -p 22,3389,5985,5986')
        for host in [x for x in nm.all_hosts()]:
            os_version = determine_os(nm, host)
            if os_version == "Windows":
                print(f"Windows Host ",end="")
                create_log_file(host)
                log(f'{LOG_FOLDER}/{host}.txt', f"Found Windows Host: {host}")
                # determine_os_version
            else:
                print(f"Unix Host ",end="")
                create_log_file(host)
                log(f'{LOG_FOLDER}/{host}.txt', f"Found Unix Host: {host}")

                if GRAFANA_IP is None:
                    find_grafana(host)
                if os_version == "Ubuntu":
                    global PASSWORD_MANAGER_IP
                    if PASSWORD_MANAGER_IP is None:
                        PASSWORD_MANAGER_IP = host
            lport = nm[host]['tcp'].keys()
            found_hosts[host] = {
                    'SSH': False,
                    'RDP': False,
                    'WinRM_HTTP': False,
                    'WinRM_HTTPS': False
                }
            for port in lport:
                log(f'{LOG_FOLDER}/{host}.txt', 'port : %s\tstate : %s' % (port, nm[host]['tcp'][port]['state']))
                if port == 22 and nm[host]['tcp'][port]['state'] == 'open':
                    found_hosts[host]['SSH'] = True
                elif port == 3389 and nm[host]['tcp'][port]['state'] == 'open':
                    found_hosts[host]['RDP'] = True
                elif port == 5985 and nm[host]['tcp'][port]['state'] == 'open':
                    found_hosts[host]['WinRM_HTTP'] = True
                elif port == 5986 and nm[host]['tcp'][port]['state'] == 'open':
                    found_hosts[host]['WinRM_HTTPS'] = True
            print(f"{host}: ", end="")
            if found_hosts[host]['SSH']:
                print("SSH ", end="")
            if found_hosts[host]['RDP']:
                print("RDP ", end="")
            if found_hosts[host]['WinRM_HTTP'] or found_hosts[host]['WinRM_HTTPS']:
                print("WinRM ", end="")
            
            print("")
            print("")
            log(f'{LOG_FOLDER}/{host}.txt', "")

    return found_hosts

def find_grafana(host):
    global GRAFANA_IP
    if GRAFANA_IP is not None:
        return
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments='-p 3000')
    GRAFANA_IP = nm.all_hosts()[0]

# Attempts to gather additional information about Windows hosts
def gather_windows_info(hosts):
    command_output = {}
    for host in hosts:
        if hosts[host]['WinRM_HTTP']:
            log(f'{LOG_FOLDER}/{host}.txt', f"Attempting WinRM HTTP connection to {host}")
            try:
                session = winrm.Session(
                    host,
                    auth=(f"{DOMAIN_USERNAME}", DOMAIN_PASSWORD),
                    server_cert_validation='ignore',
                    transport='ntlm'
                )
                detect_scored_services(session, host)
                determine_os_version(session, host)
                log(IP_FILE, host)
                continue
            except Exception as e:
                print(e)
                port_scan_only(host, command_output)
        else:
            port_scan_only(host, command_output)
            pass
    return command_output

# Determines scored service via WinRM
def detect_scored_services(session, ip_address):
    log_file = f'{LOG_FOLDER}/{ip_address}.txt'
    print(f"{ip_address}: ",end="")
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

    check_http = session.run_cmd('sc query w3svc')
    if check_http.status_code != 0:
        log(log_file, "HTTP service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":80"').std_out.decode() == '':
            log(log_file, "HTTP service is not running.")
        else:
            print("HTTP:80 ",end="")
            log(log_file, "HTTP is Present")
            log(log_file, check_http.std_out.decode())

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

    check_adfs = session.run_cmd('sc query adfssrv')
    if check_adfs.status_code != 0:
        log(log_file, "ADFS service not found.")
    else:
        print("ADFS ",end="")
        log(log_file, "ADFS is Present")
        log(log_file, check_adfs.std_out.decode())

    check_https = session.run_cmd('sc query w3svc')
    if check_https.status_code != 0:
        log(log_file, "HTTPS service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":443"').std_out.decode() == '':
            log(log_file, "HTTPS service is not running.")
        else:
            print("HTTPS:443 ")
            log(log_file, "HTTPS is Present")
            log(log_file, check_https.std_out.decode())

    check_ca = session.run_cmd('sc query certsvc')
    if check_ca.status_code != 0:
        log(log_file, "Certificate Authority service not found.")
    else:
        print("CA ",end="")
        log(log_file, "Certificate Authority is Present")
        log(log_file, check_ca.std_out.decode())

    check_smb = session.run_cmd('sc query lanmanserver')
    if check_smb.status_code != 0:
        log(log_file, "SMB service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":445"').std_out.decode() == '':
            log(log_file, "SMB service is not running.")
        else:
            print("SMB:445 ")
            log(log_file, "SMB is Present")
            log(log_file, check_smb.std_out.decode())

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

def determine_os(nm, host):
    # Check OS detection results
    os_match = nm[host].get('osmatch', [])
    
    if os_match:
        # Check if any OS match indicates Windows
        for os_info in os_match:
            if 'Windows' in os_info.get('name', ''):
                return 'Windows'
            if 'Ubuntu' in os_info.get('name', ''):
                return 'Ubuntu'
            
    return None

def determine_os_version(session, ip_address):
    log_file = f'{LOG_FOLDER}/{ip_address}.txt'
    check_os_type = session.run_cmd('powershell -c Get-ItemPropertyValue \'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\' InstallationType')
    check_os_version = session.run_cmd('powershell -c Get-ItemPropertyValue \'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\' ProductName')
    if check_os_type.std_out.decode() == '':
        log(log_file, f"Could not determine OS type for {ip_address}\n")
    else:
        log(log_file, f"OS Type for {ip_address}: {check_os_type.std_out.decode().strip()}\n")
    if check_os_version.std_out.decode() == '':
        log(log_file, f"Could not determine OS version for {ip_address}\n")
    else:
        log(log_file, f"OS Version for {ip_address}: {check_os_version.std_out.decode().strip()}\n")
    print(f"{ip_address}: {check_os_version.std_out.decode().strip()} ({check_os_type.std_out.decode().strip()})\n",end="")

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
    log_file = f'{LOG_FOLDER}/{host}.txt'
    print(f"{host}: ",end="")
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
                if host not in command_output:
                    command_output[host] = f"Open ports: {port} ({service})"
                else:
                    command_output[host] += f", {port} ({service})"
        print("")
    except Exception as e:
        log(log_file, f"Port scan failed for {host}: {str(e)}")

# Adds information about Windows hosts to the Ansible inventory file
def add_to_ansible_inventory(hosts):
    pass

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Windows Reconnaissance Script to Fill Out Ansible Inventory')
    parser.add_argument('-s', required=True, help='Subnet to scan for Windows hosts (e.g., 192.168.1.0/24)')
    parser.add_argument('-u', required=True, help='Domain username for WinRM authentication')
    parser.add_argument('-p', required=True, help='Domain password for WinRM authentication')
    args = parser.parse_args()

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
    global DOMAIN_USERNAME
    global DOMAIN_PASSWORD
    global PASSWORD_MANAGER_IP
    global GRAFANA_IP

    PASSWORD_MANAGER_IP = None
    GRAFANA_IP = None

    SUBNET = args.s
    DOMAIN_USERNAME = args.u
    DOMAIN_PASSWORD = args.p
    print(f"Scanning subnet: {SUBNET} with username: {DOMAIN_USERNAME} and password: {DOMAIN_PASSWORD}")
    log(GENERAL_LOG_FILE, f"Scanning subnet: {SUBNET} with username: {DOMAIN_USERNAME}")

    found_hosts = scan_all_hosts(SUBNET)
    #print(json.dumps(found_hosts, indent=4)) #json output for debugging
    command_output = gather_windows_info(found_hosts)
    #print(json.dumps(command_output, indent=4))
    add_to_ansible_inventory(found_hosts)

if __name__ == "__main__":
    main()
