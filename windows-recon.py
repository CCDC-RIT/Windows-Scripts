# Windows Reconnaissance Script to Fill Out Ansible Inventory
import nmap
import json
import winrm
import argparse

# Global Variables
ANSIBLE_INVENTORY_FILE = 'Windows-Scripts/ansible/inventory/inventory.yml'
global SUBNET
global DOMAIN
global DOMAIN_USERNAME
global DOMAIN_PASSWORD

# Scans the given subnet for hosts
def scan_windows_hosts(subnet):
    found_hosts = {}
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments='-O -sV -p 22,3389,5985,5986')
    for host in [x for x in nm.all_hosts()]:
        print(f"Found Unknown Host: {host}")
        lport = nm[host]['tcp'].keys()
        found_hosts[host] = {
                'SSH': False,
                'RDP': False,
                'WinRM_HTTP': False,
                'WinRM_HTTPS': False
            }
        for port in lport:
            print('port : %s\tstate : %s' % (port, nm[host]['tcp'][port]['state']))
            if port == 22 and nm[host]['tcp'][port]['state'] == 'open':
                found_hosts[host]['SSH'] = True
            elif port == 3389 and nm[host]['tcp'][port]['state'] == 'open':
                found_hosts[host]['RDP'] = True
            elif port == 5985 and nm[host]['tcp'][port]['state'] == 'open':
                found_hosts[host]['WinRM_HTTP'] = True
            elif port == 5986 and nm[host]['tcp'][port]['state'] == 'open':
                found_hosts[host]['WinRM_HTTPS'] = True

    return found_hosts

# Attempts to gather additional information about Windows hosts
def gather_windows_info(hosts, domain, username, password):
    command_output = {}
    for host in hosts:
        if hosts[host]['WinRM_HTTP']:
            print(f"Attempting WinRM HTTP connection to {host}")
            try:
                session = winrm.Session(
                    f'http://{host}:5985/wsman',
                    auth=(f'{domain}\\{username}', password),
                    transport='ntlm',
                    server_cert_validation='ignore'
                )
                r = session.run_cmd('systeminfo')
                command_output[host] = r.std_out.decode()
            except Exception as e:
                command_output[host] = f"Failed to connect via WinRM HTTP: {str(e)}"
    return command_output

# Adds information about Windows hosts to the Ansible inventory file
def add_to_ansible_inventory(hosts):
    pass

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Windows Reconnaissance Script to Fill Out Ansible Inventory')
    parser.add_argument('-s', required=True, help='Subnet to scan for Windows hosts (e.g., 192.168.1.0/24)')
    parser.add_argument('-d', required=True, help='Domain name for WinRM authentication')
    parser.add_argument('-u', required=True, help='Domain username for WinRM authentication')
    parser.add_argument('-p', required=True, help='Domain password for WinRM authentication')
    args = parser.parse_args()

    # Set global variables
    SUBNET = args.s
    DOMAIN = args.d
    DOMAIN_USERNAME = args.u
    DOMAIN_PASSWORD = args.p
    print(f"Scanning subnet: {SUBNET} on domain {DOMAIN} with username: {DOMAIN_USERNAME} and password: {DOMAIN_PASSWORD}")

    found_hosts = scan_windows_hosts(SUBNET)
    #print(json.dumps(found_hosts, indent=4)) json output for debugging
    command_output = gather_windows_info(found_hosts, DOMAIN, DOMAIN_USERNAME, DOMAIN_PASSWORD)
    print(json.dumps(command_output, indent=4))
    add_to_ansible_inventory(found_hosts)

if __name__ == "__main__":
    main()
