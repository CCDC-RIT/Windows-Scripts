# IMPORTANT NEEDS TO BE ENABLED ON ALL BOXES!!!
# winrm set winrm/config/service @{AllowUnencrypted="true"}
# winrm set winrm/config/service/auth @{Basic="true"}

# Output to /opt/passwordmanager/starting_clients.txt

# Windows Reconnaissance Script to Fill Out Ansible Inventory
import os
import nmap
import json
import winrm
import argparse

# Global Variables
ANSIBLE_INVENTORY_FILE = 'Windows-Scripts/ansible/inventory/inventory.yml'
LOG_FILE = '/windows_recon_log.txt'
IP_FILE = '/opt/passwordmanager/windows_starting_clients.txt'
global SUBNET
global DOMAIN_USERNAME
global DOMAIN_PASSWORD

# Scans the given subnet for hosts
def scan_all_hosts(subnet):
    found_hosts = {}
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments='-O -p 22,3389,5985,5986')
    for host in [x for x in nm.all_hosts()]:
        if not determine_os(nm, host):
            print(f"Found Unix Host: {host}")
            log(LOG_FILE, f"Found Unix Host: {host}")
        else:
            print(f"Found Windows Host: {host}")
            log(LOG_FILE, f"Found Windows Host: {host}")
        lport = nm[host]['tcp'].keys()
        found_hosts[host] = {
                'SSH': False,
                'RDP': False,
                'WinRM_HTTP': False,
                'WinRM_HTTPS': False
            }
        for port in lport:
            print('port : %s\tstate : %s' % (port, nm[host]['tcp'][port]['state']))
            log(LOG_FILE, 'port : %s\tstate : %s' % (port, nm[host]['tcp'][port]['state']))
            if port == 22 and nm[host]['tcp'][port]['state'] == 'open':
                found_hosts[host]['SSH'] = True
            elif port == 3389 and nm[host]['tcp'][port]['state'] == 'open':
                found_hosts[host]['RDP'] = True
            elif port == 5985 and nm[host]['tcp'][port]['state'] == 'open':
                found_hosts[host]['WinRM_HTTP'] = True
            elif port == 5986 and nm[host]['tcp'][port]['state'] == 'open':
                found_hosts[host]['WinRM_HTTPS'] = True
        print("")
        log(LOG_FILE, "")

    return found_hosts

# Attempts to gather additional information about Windows hosts
def gather_windows_info(hosts, username, password):
    command_output = {}
    for host in hosts:
        if hosts[host]['WinRM_HTTP']:
            print(f"Attempting WinRM HTTP connection to {host}")
            log(LOG_FILE, f"Attempting WinRM HTTP connection to {host}")
            try:
                session = winrm.Session(
                    host,
                    auth=(username, password),
                    server_cert_validation='ignore'
                )
                detect_scored_services(session)
                log(IP_FILE, host)
                continue
            except Exception as e:
                port_scan_only(host, command_output)
        else:
            port_scan_only(host, command_output)
    return command_output

# Determines scored service via WinRM
def detect_scored_services(session):
    check_ldap = session.run_cmd('sc query ntds')
    if check_ldap.status_code != 0:
        print("LDAP service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":389"').std_out.decode() == '':
            print("LDAP service is not running.")
        else:
            print("LDAP service is running and listening on port 389.")
            log(LOG_FILE, "LDAP is Present")
            log(LOG_FILE, check_ldap.std_out.decode())
    
    check_dns = session.run_cmd('sc query dns')
    if check_dns.status_code != 0:
        print("DNS service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":53"').std_out.decode() == '':
            print("DNS service is not running.")
        else:
            print("DNS service is running and listening on port 53.")
            log(LOG_FILE, "DNS is Present")
            log(LOG_FILE, check_dns.std_out.decode())

    check_dhcp = session.run_cmd('sc query dhcpserver')
    if check_dhcp.status_code != 0:
        print("DHCP service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":67"').std_out.decode() == '':
            print("DHCP service is not running.")
        else:
            print("DHCP service is running and listening on port 67.")
            log(LOG_FILE, "DHCP is Present")
            log(LOG_FILE, check_dhcp.std_out.decode())

    check_http = session.run_cmd('sc query w3svc')
    if check_http.status_code != 0:
        print("HTTP service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":80"').std_out.decode() == '':
            print("HTTP service is not running.")
        else:
            print("HTTP service is running and listening on port 80.")
            log(LOG_FILE, "HTTP is Present")
            log(LOG_FILE, check_http.std_out.decode())

    check_https = session.run_cmd('sc query w3svc')
    if check_https.status_code != 0:
        print("HTTPS service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":443"').std_out.decode() == '':
            print("HTTPS service is not running.")
        else:
            print("HTTPS service is running and listening on port 443.")
            log(LOG_FILE, "HTTPS is Present")
            log(LOG_FILE, check_https.std_out.decode())

    check_ca = session.run_cmd('sc query certsvc')
    if check_ca.status_code != 0:
        print("Certificate Authority service not found.")
    else:
        print("Certificate Authority service is running.")
        log(LOG_FILE, "Certificate Authority is Present")
        log(LOG_FILE, check_ca.std_out.decode())

    check_smb = session.run_cmd('sc query lanmanserver')
    if check_smb.status_code != 0:
        print("SMB service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":445"').std_out.decode() == '':
            print("SMB service is not running.")
        else:
            print("SMB service is running and listening on port 445.")
            log(LOG_FILE, "SMB is Present")
            log(LOG_FILE, check_smb.std_out.decode())

    check_telnet = session.run_cmd('sc query telnet')
    if check_telnet.status_code != 0:
        print("Telnet service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":23"').std_out.decode() == '':
            print("Telnet service is not running.")
        else:
            print("Telnet service is running and listening on port 23.")
            log(LOG_FILE, "Telnet is Present")
            log(LOG_FILE, check_telnet.std_out.decode())

    check_ftp = session.run_cmd('sc query ftpsvc')
    if check_ftp.status_code != 0:
        print("FTP service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":21"').std_out.decode() == '':
            print("FTP service is not running.")
        else:
            print("FTP service is running and listening on port 21.")
            log(LOG_FILE, "FTP is Present")
            log(LOG_FILE, check_ftp.std_out.decode())

    check_ntp = session.run_cmd('sc query w32time')
    if check_ntp.status_code != 0:
        print("NTP service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":123"').std_out.decode() == '':
            print("NTP service is not running.")
        else:
            print("NTP service is running and listening on port 123.")
            log(LOG_FILE, "NTP is Present")
            log(LOG_FILE, check_ntp.std_out.decode())

    check_ssh = session.run_cmd('sc query sshd')
    if check_ssh.status_code != 0:
        print("SSH service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":22"').std_out.decode() == '':
            print("SSH service is not running.")
        else:
            print("SSH service is running and listening on port 22.")
            log(LOG_FILE, "SSH is Present")
            log(LOG_FILE, check_ssh.std_out.decode())

    check_rdp = session.run_cmd('sc query termservice')
    if check_rdp.status_code != 0:
        print("RDP service not found.")
    else:
        if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":3389"').std_out.decode() == '':
            print("RDP service is not running.")
        else:
            print("RDP service is running and listening on port 3389.")
            log(LOG_FILE, "RDP is Present")
            log(LOG_FILE, check_rdp.std_out.decode())

def determine_os(nm, host):
    # Check OS detection results
    os_match = nm[host].get('osmatch', [])
    is_windows = False
    
    if os_match:
        # Check if any OS match indicates Windows
        for os_info in os_match:
            if 'Windows' in os_info.get('name', ''):
                is_windows = True
                break
    
    # Skip non-Windows hosts
    if not is_windows:
        return False
    return True

def log(file, content):
    with open(file, 'a') as log_file:
        log_file.write(content + '\n')

def port_scan_only(host, command_output):
    print(f"Could not connect to {host} via WinRM, downgrading to Port Scanning only.")
    log(LOG_FILE, f"Could not connect to {host} via WinRM, downgrading to Port Scanning only.")
    try:
        ps = nmap.PortScanner()
        ps.scan(hosts=host, arguments='-sV -p 21,22,23,53,67,80,123,389,443,445,3389,5985,5986')
        lport = ps[host]['tcp'].keys()
        
        # Log open ports found
        for port in lport:
            port_state = ps[host]['tcp'][port]['state']
            if port_state == 'open':
                service = 'SSH' if port == 22 else 'RDP' if port == 3389 else 'Unknown'
                log(LOG_FILE, f"{host}:{port} ({service}) is {port_state}")
                print(f"{host}:{port} ({service}) is {port_state}")
                if host not in command_output:
                    command_output[host] = f"Open ports: {port} ({service})"
                else:
                    command_output[host] += f", {port} ({service})"
    except Exception as e:
        log(LOG_FILE, f"Port scan failed for {host}: {str(e)}")

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

    # Make sure log file is empty and exists
    if not os.path.exists(LOG_FILE):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    open(LOG_FILE, 'w').close()

    # Make sure IP file exists
    if not os.path.exists(IP_FILE):
        os.makedirs(os.path.dirname(IP_FILE), exist_ok=True)
    open(IP_FILE, 'w').close()

    # Set global variables
    SUBNET = args.s
    DOMAIN_USERNAME = args.u
    DOMAIN_PASSWORD = args.p
    print(f"Scanning subnet: {SUBNET} with username: {DOMAIN_USERNAME} and password: {DOMAIN_PASSWORD}")
    log(LOG_FILE, f"Scanning subnet: {SUBNET} with username: {DOMAIN_USERNAME}")

    found_hosts = scan_all_hosts(SUBNET)
    #print(json.dumps(found_hosts, indent=4)) #json output for debugging
    command_output = gather_windows_info(found_hosts, DOMAIN_USERNAME, DOMAIN_PASSWORD)
    print(json.dumps(command_output, indent=4))
    add_to_ansible_inventory(found_hosts)

if __name__ == "__main__":
    main()
