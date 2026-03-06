# IMPORTANT NEEDS TO BE ENABLED ON ALL BOXES!!!
#https://community.fortinet.com/t5/FortiSOAR-Knowledge-Base/Troubleshooting-Tip-Exchange-Microsoft-WinRM-Connector-Error/ta-p/324015

# Windows Reconnaissance Script to Fill Out Ansible Inventory
import os
import nmap
import winrm
import argparse
import paramiko
import socket
import re
import ipaddress

# Global File Locations
WINDOWS_INVENTORY_FILE = '/Windows-Scripts/ansible/inventory/inventory.yml'
LINUX_INVENTORY_FILE = '/home/inventory.ini' # Gets correctly set in main
WINDOWS_IP_FILE = '/opt/passwordmanager/windows_starting_clients.txt'
LINUX_IP_FILE = '/opt/passwordmanager/linux_starting_clients.txt'
ALL_IP_FILE = '/opt/passwordmanager/starting_clients.txt'
TOPOLOGY_FILE = '/Windows-Scripts/topology.csv'

# Global Variables
global DOMAIN_CREDENTIALS
global LINUX_CREDENTIALS
global SCRIPTS_PATH
global PASSWORD_MANAGER_IP
global GRAFANA_IP
global GRAYLOG_IP
global WAZUH_IP
global LOCAL_IP
global HOME_DIR_FOUND
global HOST_INFO
global RUN_WINDOWS
global RUN_LINUX
global SIEM_TYPE

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

# Scans the given subnet for hosts
def scan_all_hosts(subnet):
    global HOST_INFO
    nm = nmap.PortScanner()
    # param gets passed as comma separated, nmap wants spaces
    subnet = subnet.replace(',', ' ')
    # Use -6 flag for IPv6 scanning
    if ':' in subnet:
        nm.scan(hosts=subnet, arguments='-T5 -n -Pn --open -O -6 --min-parallelism 50 --max-parallelism 100 --min-rate 5000 --max-retries 1 -p 22,3389,5985,5986')
    else:
        nm.scan(hosts=subnet, arguments='-T5 -n -Pn --open -O --min-rate 5000 --max-retries 1  -p 22,3389,5985,5986')
    for host in [x for x in nm.all_hosts()]:
        lport = nm[host]['tcp'].keys()

        HOST_INFO[host] = {
            'OS': '',
            'OS_Version': '',
            'OS_Short_Name': '',
            'Username': None,
            'Password': None,
            'Hostname': None,
            'Domain': None,
            'Services': set(),
        }

        for port in lport:
            if port == 22 and nm[host]['tcp'][port]['state'] == 'open':
                HOST_INFO[host]['Services'].add('SSH')
            elif port == 3389 and nm[host]['tcp'][port]['state'] == 'open':
                HOST_INFO[host]['Services'].add('RDP')
            elif port == 5985 and nm[host]['tcp'][port]['state'] == 'open':
                HOST_INFO[host]['Services'].add('WinRM_HTTP')
            elif port == 5986 and nm[host]['tcp'][port]['state'] == 'open':
                HOST_INFO[host]['Services'].add('WinRM_HTTPS')

        os_version = determine_os(nm, host)

        if os_version == "Windows" or ('WinRM_HTTP' in HOST_INFO[host]['Services'] or 'WinRM_HTTPS' in HOST_INFO[host]['Services'] or 'RDP' in HOST_INFO[host]['Services']):
            HOST_INFO[host]['OS'] = 'Windows'
            print(f"Windows Host {host} detected:\n",end="")
        else:
            print(f"Unix Host {host} detected:\n",end="")
            HOST_INFO[host]['OS'] = os_version
            if GRAFANA_IP is None and SIEM_TYPE == 'grafana':
                find_grafana(host)
            elif GRAYLOG_IP is None and SIEM_TYPE == 'graylog':
                find_graylog(host)
            elif WAZUH_IP is None and SIEM_TYPE == 'wazuh':
                find_wazuh(host)

        if HOST_INFO[host]['Services'] == set():
            print("No Detected Remoting Services", end="")
        else:
            if 'SSH' in HOST_INFO[host]['Services'] or 'RDP' in HOST_INFO[host]['Services'] or 'WinRM_HTTP' in HOST_INFO[host]['Services'] or 'WinRM_HTTPS' in HOST_INFO[host]['Services']:
                print("Detected Remoting Services: ", end="")
                for service in HOST_INFO[host]['Services']:
                    print(f"{service} ", end="")

        print("\n")

def find_grafana(host):
    global GRAFANA_IP
    nm = nmap.PortScanner()
    if ":" in host:
        nm.scan(hosts=host, arguments='-6 -p 3000,9000')
    else:
        nm.scan(hosts=host, arguments='-p 3000,9000')
    grafana_ports = [3000,9000]
    for port in grafana_ports:
        if nm[host].has_tcp(port) and nm[host]['tcp'][port]['state'] == 'open':
            GRAFANA_IP = host
            print(f"Set as Grafana IP\n",end="")
            break

def find_graylog(host):
    global GRAYLOG_IP
    nm = nmap.PortScanner()
    if ":" in host:
        nm.scan(hosts=host, arguments='-6 -p 514,5044,5555,9000,9200,9300,27017')
    else:
        nm.scan(hosts=host, arguments='-p 514,5044,5555,9000,9200,9300,27017')
    graylog_ports = [514,5044,5555,9000,9200,9300,27017]
    for port in graylog_ports:
        if nm[host].has_tcp(port) and nm[host]['tcp'][port]['state'] == 'open':
            GRAYLOG_IP = host
            print(f"Set as Graylog IP\n",end="")
            break

def find_wazuh(host):
    global WAZUH_IP
    nm = nmap.PortScanner()
    if ":" in host:
        nm.scan(hosts=host, arguments='-6 -p 1514')
    else:
        nm.scan(hosts=host, arguments='-p 1514')
    if nm[host].has_tcp(1514) and nm[host]['tcp'][1514]['state'] == 'open':
        WAZUH_IP = host
        print(f"Set as Wazuh IP\n",end="")

# Attempts to gather additional information about Windows hosts
def gather_info(subnet):
    global HOST_INFO

    for host in HOST_INFO.keys():
        # host regex match to subnet
        ip_obj = ipaddress.ip_address(host)  # Parse IP
        subnet_obj = ipaddress.ip_network(subnet, strict=False)
        if ip_obj in subnet_obj:
            if HOST_INFO[host]['OS'] == "Windows" and RUN_WINDOWS:
                if 'WinRM_HTTP' in HOST_INFO[host]['Services'] or 'WinRM_HTTPS' in HOST_INFO[host]['Services']:
                    gather_windows_info(host)
                    if HOST_INFO[host]['Username'] is None or HOST_INFO[host]['Password'] is None:
                        print(f"Windows Host {host} WinRM Authentication Failed, Running Port Scan:\n",end="")
                        windows_port_scan_only(host)
                else:
                    print(f"Windows Host {host} has WinRM Disabled, Running Port Scan:\n",end="")
                    windows_port_scan_only(host)
            elif LINUX_CREDENTIALS is not None and HOST_INFO[host]['OS'] == 'Linux' and RUN_LINUX:
                if 'SSH' in HOST_INFO[host]['Services']:
                    gather_linux_info(host)
                else:
                    print(f"Unix Host {host} has SSH Disabled, Running Port Scan:\n",end="")
                    linux_port_scan_only(host)
            services_str = ','.join(sorted(HOST_INFO[host]['Services'])) if HOST_INFO[host]['Services'] else 'None'
            os_version = HOST_INFO[host]['OS_Version']
            if os_version:
                os_version = re.sub(r'^(.*[0-9]).*$', r'\1', os_version)

            if not (host.split(".")[3] == "254" or host.split(".")[3] == "255"):
                log(TOPOLOGY_FILE, f"{subnet},{host},{HOST_INFO[host]['Hostname']},{HOST_INFO[host]['Domain']},{os_version},\"{services_str}\"")

def gather_windows_info(host):
    for i in range(len(DOMAIN_CREDENTIALS)):
        username = DOMAIN_CREDENTIALS[i][0]
        password = DOMAIN_CREDENTIALS[i][1]
        try:
            # Wrap IPv6 addresses in brackets
            host_addr = f"[{host}]" if ':' in host and not host.startswith('[') else host
            session = winrm.Session(
                f'http://{host_addr}:5985/wsman',
                auth=(f"{username}", password),
                server_cert_validation='ignore',
                transport='ntlm'
            )
            HOST_INFO[host]['Username'] = username
            HOST_INFO[host]['Password'] = password
            print(f"Windows Host {host}:")
            print(f"Credentials Used: {username}:{password}")
            detect_windows_scored_services(session, host)
            determine_windows_os_version(session, host)
            log(WINDOWS_IP_FILE, host)
            log(ALL_IP_FILE, host)
            continue
        except Exception as e:
            pass

def gather_linux_info(host):
    for i in range(len(LINUX_CREDENTIALS)):
        username = LINUX_CREDENTIALS[i][0]
        password = LINUX_CREDENTIALS[i][1]
        try:
            HOST_INFO[host]['Username'] = username
            HOST_INFO[host]['Password'] = password
            print(f"Linux Host {host}:")
            print(f"Credentials Used: {username}:{password}")
            session = paramiko.SSHClient()
            session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            session.connect(host, username=username, password=password, timeout=10)
            detect_unix_scored_services(session, host)
            determine_unix_os_version(session, host)
            log(LINUX_IP_FILE, host)
            log(ALL_IP_FILE, host)
            session.close()
        except Exception as e:
            print(f"Unexpected error connecting to {host}: {str(e)}.. Falling back to port scan")
            linux_port_scan_only(host)
            log(LINUX_IP_FILE, host)
            log(ALL_IP_FILE, host)
            continue

# Determines scored service via WinRM
def detect_windows_scored_services(session, ip_address):
    global HOST_INFO

    try:
        # Detects hostname (also serves as a basic command to verify WinRM connection works)
        basic_query = session.run_cmd('hostname')
        if basic_query.status_code == 0:
            hostname = basic_query.std_out.decode().strip()
            HOST_INFO[ip_address]['Hostname'] = hostname
            print("Detected Potential Scored Services: ",end="")
        
        # Detects domain
        domain_query = session.run_cmd('powershell -c "(Get-WmiObject Win32_ComputerSystem).Domain"')
        if domain_query.status_code == 0:
            domain = domain_query.std_out.decode().strip()
            if domain and domain.lower() != 'workgroup':
                HOST_INFO[ip_address]['Domain'] = domain

        check_ftp = session.run_cmd('sc query ftpsvc')
        if check_ftp.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":21"').std_out.decode() != '':
                print("FTP:21 ",end="")
                HOST_INFO[ip_address]['Services'].add('FTP')

        check_ssh = session.run_cmd('sc query sshd')
        if check_ssh.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":22"').std_out.decode() != '':
                print("SSH:22 ",end="")
                HOST_INFO[ip_address]['Services'].add('SSH')

        check_telnet = session.run_cmd('sc query telnet')
        if check_telnet.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":23"').std_out.decode() != '':
                print("Telnet:23 ",end="")
                HOST_INFO[ip_address]['Services'].add('Telnet')

        check_dns = session.run_cmd('sc query dns')
        if check_dns.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":53"').std_out.decode() != '':
                print("DNS:53 ",end="")
                HOST_INFO[ip_address]['Services'].add('DNS')

        check_dhcp = session.run_cmd('sc query dhcpserver')
        if check_dhcp.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":67"').std_out.decode() != '':
                print("DHCP:67 ",end="")
                HOST_INFO[ip_address]['Services'].add('DHCP')

        check_http_iis = session.run_cmd('sc query w3svc')
        if check_http_iis.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":80"').std_out.decode() != '':
                print("HTTP_IIS:80 ",end="")
                HOST_INFO[ip_address]['Services'].add('HTTP')
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":443"').std_out.decode() != '':
                print("HTTPS_IIS:443 ",end="")
                HOST_INFO[ip_address]['Services'].add('HTTPS')

        check_http_nginx = session.run_cmd('sc query nginx')
        if check_http_nginx.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":80"').std_out.decode() != '':
                print("HTTP_Nginx:80 ",end="")
                HOST_INFO[ip_address]['Services'].add('HTTP')
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":443"').std_out.decode() != '':
                print("HTTPS_Nginx:443 ",end="")
                HOST_INFO[ip_address]['Services'].add('HTTPS')

        check_http_apache = session.run_cmd('sc query Apache2.4')
        if check_http_apache.status_code != 0:
            check_http_apache = session.run_cmd('sc query Apache24')
            if check_http_apache.status_code != 0:
                check_http_apache = session.run_cmd('sc query Apache')
        if check_http_apache.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":80"').std_out.decode() != '':
                print("HTTP_Apache:80 ",end="")
                HOST_INFO[ip_address]['Services'].add('HTTP')
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":443"').std_out.decode() != '':
                print("HTTPS_Apache:443 ",end="")
                HOST_INFO[ip_address]['Services'].add('HTTPS')

        check_ntp = session.run_cmd('sc query w32time')
        if check_ntp.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":123"').std_out.decode() != '':
                print("NTP:123 ",end="")
                HOST_INFO[ip_address]['Services'].add('NTP')

        check_ldap = session.run_cmd('sc query ntds')
        if check_ldap.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":389"').std_out.decode() != '':
                print("LDAP:389 ", end="")
                HOST_INFO[ip_address]['Services'].add('LDAP')

        check_adfs = session.run_cmd('sc query adfssrv')
        if check_adfs.status_code == 0:
            print("ADFS ",end="")
            HOST_INFO[ip_address]['Services'].add('ADFS')

        check_ca = session.run_cmd('sc query certsvc')
        if check_ca.status_code == 0:
            print("CA ",end="")
            HOST_INFO[ip_address]['Services'].add('CA')

        check_smb = session.run_cmd('powershell -c \"Get-SmbShare -IncludeHidden | ? Name -notin \'ADMIN$\',\'C$\',\'IPC$\'\"')
        if check_smb.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":445"').std_out.decode() != '':
                print("SMB:445 ",end="")
                HOST_INFO[ip_address]['Services'].add('SMB')

        check_rdp = session.run_cmd('sc query termservice')
        if check_rdp.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":3389"').std_out.decode() != '':
                print("RDP:3389",end="")
                HOST_INFO[ip_address]['Services'].add('RDP')
        print("\n",end="")
    except Exception as e:
        print("Failed to create WinRM session, attempting port scan\n",end="")
        windows_port_scan_only(ip_address)
        print("")

def detect_unix_scored_services(session, ip_address):
    global HOST_INFO

    try:
        print("Detected Potential Scored Services: ",end="")
        _, stdout, _ = session.exec_command('ss -tulnp')
        lines = stdout.read().decode().strip()
        for line in lines.split('\n'):
            tokens = line.split()
            protocol = tokens[0]
            local_address = tokens[4]
            local_address_tokens = local_address.split(':')
            port = local_address_tokens[-1]
            if "127.0.0" not in local_address and "::1" not in local_address and port != "Local":
                HOST_INFO[ip_address]['Services'].add(f"{protocol}:{port}")
        for addy in HOST_INFO[ip_address]['Services']:
            if not (addy == "SSH"):
                print(f"{addy}",end=" ")
        print("")

    except Exception as e:
        print("Unexpected SSH error\n",end="")

def determine_os(nm, host):
    # Check OS detection results
    os_match = nm[host].get('osmatch', [])
    if os_match:
        # Check all matches for Windows first (higher priority)
        for os_info in os_match:
            if 'Windows' in os_info.get('name', ''):
                return 'Windows'

        # If no Windows match found, check for Linux/Unix
        for os_info in os_match:
            if 'Linux' in os_info.get('name', ''):
                return 'Linux'

    return 'FreeBSD'  # Default to FreeBSD if no matches found

def determine_windows_os_version(session, ip_address):
    global HOST_INFO

    # Determines Windows OS Version
    check_os_type = session.run_cmd('powershell -c Get-ItemPropertyValue \'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\' InstallationType')
    check_os_version = session.run_cmd('powershell -c Get-ItemPropertyValue \'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\' ProductName')
    if check_os_type.std_out.decode() != '' and check_os_version.std_out.decode() != '':
        print(f"Detected OS: {check_os_version.std_out.decode().strip()} ({check_os_type.std_out.decode().strip()})\n",end="")
        HOST_INFO[ip_address]['OS_Version'] = f"{check_os_version.std_out.decode().strip()} ({check_os_type.std_out.decode().strip()})"
    else:
        if check_os_type.std_out.decode() == '':
            print("Could not determine OS Type\n",end="")
        else:
            print(f"Detected OS Type: {check_os_type.std_out.decode().strip()}",end="")
            HOST_INFO[ip_address]['OS_Version'] = f"{check_os_type.std_out.decode().strip()}"
        if check_os_version.std_out.decode() == '':
            print("Could not determine OS Version\n",end="")
        else:
            print(f"Detected OS Version: {check_os_version.std_out.decode().strip()}",end="")
            HOST_INFO[ip_address]['OS_Version'] += f" {check_os_version.std_out.decode().strip()}"
    print("")

def determine_unix_os_version(session, ip_address):
    global HOST_INFO

    try:
        _, stdout, _ = session.exec_command('cat /etc/os-release | grep PRETTY_NAME | cut -d "=" -f2 | tr -d \'"\'')
        os_info = stdout.read().decode().strip()
        if os_info == '':
            _, stdout, _ = session.exec_command('freebsd-version')
            os_info = "FreeBSD " + stdout.read().decode().strip()
        print(f"Detected OS: {os_info}\n",end="")
        HOST_INFO[ip_address]['OS_Version'] = os_info
        if ("Ubuntu" in os_info or "Rocky" in os_info) and "443" not in HOST_INFO[ip_address]['Services']:
            global PASSWORD_MANAGER_IP
            if PASSWORD_MANAGER_IP is None:
                PASSWORD_MANAGER_IP = ip_address
                print(f"Set as Password Manager IP\n",end="")

        if "Ubuntu" in os_info:
            HOST_INFO[ip_address]['OS_Short_Name'] = 'Ubuntu'
        elif "Debian" in os_info:
            HOST_INFO[ip_address]['OS_Short_Name'] = 'Debian'
        elif "CentOS" in os_info:
            HOST_INFO[ip_address]['OS_Short_Name'] = 'CentOS'
        elif "FreeBSD" in os_info:
            HOST_INFO[ip_address]['OS_Short_Name'] = 'FreeBSD'
        elif "Rocky" in os_info:
            HOST_INFO[ip_address]['OS_Short_Name'] = 'Rocky'
        elif "AlmaLinux" in os_info:
            HOST_INFO[ip_address]['OS_Short_Name'] = 'AlmaLinux'
        elif "Red Hat" in os_info or "RedHat" in os_info:
            HOST_INFO[ip_address]['OS_Short_Name'] = 'RedHat'
        elif "Fedora" in os_info:
            HOST_INFO[ip_address]['OS_Short_Name'] = 'Fedora'
        elif "Arch Linux" in os_info:
            HOST_INFO[ip_address]['OS_Short_Name'] = 'ArchLinux'
        elif "openSUSE" in os_info:
            HOST_INFO[ip_address]['OS_Short_Name'] = 'openSUSE'
        elif "Alpine" in os_info:
            HOST_INFO[ip_address]['OS_Short_Name'] = 'Alpine'
        elif "Amazon Linux" in os_info:
            HOST_INFO[ip_address]['OS_Short_Name'] = 'AmazonLinux'

        # Get Hostname
        _, stdout, _ = session.exec_command('hostname')
        hostname = stdout.read().decode().strip()
        HOST_INFO[ip_address]['Hostname'] = hostname

        # Get Domain
        try:
            _, stdout, _ = session.exec_command('realm list | grep "realm-name" | awk -F\': \' \'{print $2}\'')
            domain = stdout.read().decode().strip()
            if domain:
                HOST_INFO[ip_address]['Domain'] = domain
        except:
            pass

        session.close()
    except Exception as e:
        print(f"Unexpected SSH Error\n",end="")
    print("")

def log(file, content):
    with open(file, 'a') as log_file:
        log_file.write(content + '\n')

def windows_port_scan_only(host):
    global HOST_INFO

    print("Detected Potential Scored Services: ",end="")
    try:
        ps = nmap.PortScanner()
        # Use -6 flag for IPv6 scanning
        if ':' in host:
            ps.scan(hosts=host, arguments='-n -Pn -p 21,22,23,53,67,80,123,389,443,445,1500,3389,5985,5986 -6')
        else:
            ps.scan(hosts=host, arguments='-n -Pn -p 21,22,23,53,67,80,123,389,443,445,1500,3389,5985,5986')
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
                print(f"{service}:{port} ",end="")
                HOST_INFO[host]['Services'].add(service)
        print("\n",end="")
    except Exception as e:
        print(f"Port scan failed: {str(e)}\n",end="")

def linux_port_scan_only(host):
    global HOST_INFO

    print("Detected Potential Scored Services: ",end="")
    try:
        ps = nmap.PortScanner()
        # Use -6 flag for IPv6 scanning
        if ':' in host:
            ps.scan(hosts=host, arguments='-n -Pn -p 1-65535 -6')
        else:
            ps.scan(hosts=host, arguments='-n -Pn -p 1-65535')
        port_dict = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            80: "HTTP",
            123: "NTP",
            443: "HTTPS",
            445: "SMB",
            514: "Graylog",
            3000: "Grafana",
            5044: "Graylog",
            5555: "Graylog",
            9000: "Graylog",
            9200: "Graylog",
            9300: "Graylog",
            27017: "Graylog",
        }
        lport = ps[host]['tcp'].keys()

        # Log open ports found
        for port in lport:
            port_state = ps[host]['tcp'][port]['state']
            if port_state == 'open':
                service = port_dict.get(port, f"Unknown ({port})")
                print(f"tcp:{port} ",end="")
                HOST_INFO[host]['Services'].add(f"tcp:{port}")
        print("\n\n",end="")
    except Exception as e:
        print(f"Port scan failed: {str(e)}\n",end="")

def get_local_ip():
    global LOCAL_IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        LOCAL_IP = s.getsockname()[0]
        s.close()
    except Exception as e:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2001:4860:4860::8888", 80))
        LOCAL_IP = s.getsockname()[0]
        s.close()

def create_linux_ansible_inventory():
    global HOST_INFO
    global LINUX_INVENTORY_FILE
    print(f"Adding hosts to Ansible inventory file: {LINUX_INVENTORY_FILE}\n")

    ansible_host_list = "[all]\n"
    with open(LINUX_IP_FILE, "r") as Hosts:
        for line in Hosts:
            ansible_host_list += (line)
    ansible_host_list += f"""
[logging]
{GRAFANA_IP}

[kube]

[kubemgr]

[alpine]
"""
    with open(LINUX_IP_FILE, "r") as Hosts:
        for line in Hosts:
            ip = line.strip()
            if ip in HOST_INFO and HOST_INFO[ip]['OS'] == 'Linux' and HOST_INFO[ip]['OS_Short_Name'] == 'Alpine':
                ansible_host_list += (line)
                
    ansible_host_list += f"""\n[alpine:vars]
ansible_become_method=doas
"""
                
    # Determine which SIEM IP to use based on SIEM_TYPE
    siem_ip = None
    if SIEM_TYPE == 'grafana':
        siem_ip = GRAFANA_IP
    elif SIEM_TYPE == 'graylog':
        siem_ip = GRAYLOG_IP
    elif SIEM_TYPE == 'wazuh':
        siem_ip = WAZUH_IP
    
    ansible_host_list += f"""\n[all:vars]
controller_in_scope_allow_ip=""
ansible_connection=ssh
ssh_port=22
backup_dir="/usr/share/fonts/roboto-mono"
quarantine="/usr/share/fonts/quar-mono"
audit_dir="/opt/audit"
password_manager_ip="{PASSWORD_MANAGER_IP if PASSWORD_MANAGER_IP is not None else ''}"{' #REPLACE' if PASSWORD_MANAGER_IP is None else ''}
siem_ip="{siem_ip if siem_ip is not None else ''}"{' #REPLACE' if siem_ip is None else ''}
stabvest_controller_ip="{LOCAL_IP if LOCAL_IP is not None else ''}"{' #REPLACE' if LOCAL_IP is None else ''}
ansible_control_ip="{LOCAL_IP if LOCAL_IP is not None else ''}"{' #REPLACE' if LOCAL_IP is None else ''} 
firewall_logging=true
siem="{SIEM_TYPE.capitalize() if SIEM_TYPE is not None else ''}"{' #REPLACE' if SIEM_TYPE is None else ''}
"""
    for host in HOST_INFO.keys():
        if HOST_INFO[host]['OS'] == 'Linux':
            scored_ports_tcp = []
            scored_ports_udp = []
            for service in HOST_INFO[host]['Services']:
                if ':' in service:
                    protocol, port = service.split(':')
                    if protocol.lower() == 'tcp':
                        scored_ports_tcp.append(port)
                    elif protocol.lower() == 'udp':
                        scored_ports_udp.append(port)

            ansible_host_list += f"""
[{HOST_INFO[host]['OS_Short_Name']}_{HOST_INFO[host]['Hostname']}_{host.replace('.', '_').replace(':', '_')}]
{host}

[{HOST_INFO[host]['OS_Short_Name']}_{HOST_INFO[host]['Hostname']}_{host.replace('.', '_').replace(':', '_')}:vars]
ansible_user="{HOST_INFO[host]['Username'] if HOST_INFO[host]['Username'] is not None else ''}{' #REPLACE' if HOST_INFO[host]['Username'] is None else ''}"
ansible_password="{HOST_INFO[host]['Password'] if HOST_INFO[host]['Password'] is not None else ''}{' #REPLACE' if HOST_INFO[host]['Password'] is None else ''}"
ansible_become_password="{HOST_INFO[host]['Password'] if HOST_INFO[host]['Password'] is not None else ''}{' #REPLACE' if HOST_INFO[host]['Password'] is None else ''}"
scored_ports_tcp={ scored_ports_tcp if scored_ports_tcp else [] }
scored_ports_udp={ scored_ports_udp if scored_ports_udp else [] }
"""
    with open(LINUX_INVENTORY_FILE, 'w') as inventory_file:
        inventory_file.write(ansible_host_list)

# Adds information about Windows hosts to the Ansible inventory file
def create_windows_ansible_inventory():
    global HOST_INFO

    print(f"Adding hosts to Ansible inventory file: {WINDOWS_INVENTORY_FILE}\n")

    adfs_backup_password = os.urandom(12).hex()
    
    # Determine which SIEM IP to use based on SIEM_TYPE
    siem_ip = None
    if SIEM_TYPE == 'grafana':
        siem_ip = GRAFANA_IP
    elif SIEM_TYPE == 'graylog':
        siem_ip = GRAYLOG_IP
    elif SIEM_TYPE == 'wazuh':
        siem_ip = WAZUH_IP

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
        siem_IP: "{siem_ip if siem_ip is not None else ''}"{' #REPLACE' if siem_ip is None else ''}
        siem_name: "{SIEM_TYPE.capitalize() if SIEM_TYPE is not None else ''}"{' #REPLACE' if SIEM_TYPE is None else ''}
        adfs_backup_password: "{adfs_backup_password}"
        stabvest_ip: "{LOCAL_IP if LOCAL_IP is not None else ''}"{' #REPLACE' if LOCAL_IP is None else ''}
        winrm_ip: "{LOCAL_IP if LOCAL_IP is not None else ''}"{' #REPLACE' if LOCAL_IP is None else ''}
      children:
        """

    for host in HOST_INFO.keys():
        server_type = "none"
        if 'ADFS' in HOST_INFO[host]['Services']:
            server_type = "adfs"
        elif 'LDAP' in HOST_INFO[host]['Services']:
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
        scored_services.add('HTTP') if 'CA' in HOST_INFO[host]['Services'] else None
        scored_services.add('HTTPS') if 'ADFS' in HOST_INFO[host]['Services'] else None
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
            ansible_header_content += f"""win_{host.replace('.', '_').replace(':', '_')}:
          vars:
            ansible_user: "{HOST_INFO[host]['Username'] if HOST_INFO[host]['Username'] is not None else ''}{' #REPLACE' if HOST_INFO[host]['Username'] is None else ''}"
            ansible_password: "{HOST_INFO[host]['Password'] if HOST_INFO[host]['Password'] is not None else ''}{' #REPLACE' if HOST_INFO[host]['Password'] is None else ''}"
            scored_services: "{scored_services}"
            is_win_server: "{str(is_win_server).lower()}"
            is_server_core: "{str(is_server_core).lower()}"
            server_type: "{server_type}"
          hosts:
            {host}:
        """
    with open(WINDOWS_INVENTORY_FILE, 'w') as inventory_file:
        inventory_file.write(ansible_header_content)

def find_home_directory():
    global LINUX_INVENTORY_FILE
    global HOME_DIR_FOUND

    HOME_DIR_FOUND = False
    with os.scandir("/home/") as entries:
        for homedir in entries:
            if not homedir.is_file():
                with os.scandir(f"/home/{homedir.name}/") as userdir:
                    for folder in userdir:
                        if folder.name == "linux-ansible":
                            HOME_DIR_FOUND = True
                            LINUX_INVENTORY_FILE = f"/home/{homedir.name}/linux-ansible/inventory/inventory.ini"

    if not HOME_DIR_FOUND:
        print(f"Could not find linux-ansible directory, Inventory saved to {LINUX_INVENTORY_FILE}")

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Windows Reconnaissance Script to Fill Out Ansible Inventory')
    parser.add_argument('-s4', required=True, help='Subnet(s) to scan for Windows hosts (e.g., 192.168.1.0/24)')
    parser.add_argument('-s6', required=False, help='IPv6 Subnet(s) to scan for Windows hosts (e.g., 2001:0db8::/32)')
    parser.add_argument('-wc', required=True, help='Windows Domain Credentials in the format username:password,username:password')
    parser.add_argument('-lc', required=True, help='Linux Credentials in the format username:password,username:password')
    parser.add_argument('-sp', required=True, help='Scripts Path')
    parser.add_argument('-windows', action='store_true', help='Choose to only run reconnaissance on Windows hosts')
    parser.add_argument('-linux', action='store_true', help='Choose to only run reconnaissance on Unix hosts')
    parser.add_argument('-siem', required=False, default="Grafana", help='Choose the SIEM being used (e.g., Grafana, Graylog, Wazuh)')
    args = parser.parse_args()

    print("\n=======================================GENERAL SETUP=======================================\n\n")

    # Get rid of old ip files and topology file
    os.system('sudo rm -rf /opt/passwordmanager/')

    # Create new files for IP addresses and topology
    if not os.path.exists(WINDOWS_IP_FILE):
        os.makedirs(os.path.dirname(WINDOWS_IP_FILE), exist_ok=True)
        print(f"IP file created: {WINDOWS_IP_FILE}")
    else:
        print(f"IP file found: {WINDOWS_IP_FILE}")

    if not os.path.exists(LINUX_IP_FILE):
        os.makedirs(os.path.dirname(LINUX_IP_FILE), exist_ok=True)
        print(f"IP file created: {LINUX_IP_FILE}")
    else:
        print(f"IP file found: {LINUX_IP_FILE}")

    if not os.path.exists(ALL_IP_FILE):
        os.makedirs(os.path.dirname(ALL_IP_FILE), exist_ok=True)
        print(f"IP file created: {ALL_IP_FILE}")
    else:
        print(f"IP file found: {ALL_IP_FILE}")

    # Make sure Topology CSV file exists
    if not os.path.exists(TOPOLOGY_FILE):
        os.makedirs(os.path.dirname(TOPOLOGY_FILE), exist_ok=True)
        print(f"Topology file created: {TOPOLOGY_FILE}")
    else:
        print(f"Topology file found: {TOPOLOGY_FILE}")
    with open(TOPOLOGY_FILE, 'w') as topology_file:
        topology_file.write('subnet,ip,hostname,domain,os,services' + '\n')

    # Set global variables
    global DOMAIN_CREDENTIALS
    global LINUX_CREDENTIALS
    global PASSWORD_MANAGER_IP
    global GRAFANA_IP
    global GRAYLOG_IP
    global WAZUH_IP
    global SCRIPTS_PATH
    global SIEM_TYPE

    # Gathers Command Line Arguments
    SCRIPTS_PATH = args.sp
    subnet = args.s4
    ipv6_subnet = args.s6 if args.s6 is not None else None
    SIEM_TYPE = args.siem.lower() if args.siem is not None else None

    # Initialize Important System IPs to None
    PASSWORD_MANAGER_IP = None
    GRAFANA_IP = None
    GRAYLOG_IP = None
    WAZUH_IP = None

    global HOST_INFO
    HOST_INFO = {}

    get_local_ip()

    global RUN_WINDOWS
    global RUN_LINUX
    RUN_WINDOWS = args.windows
    RUN_LINUX = args.linux
    if not args.windows and not args.linux:
        RUN_WINDOWS = True
        RUN_LINUX = True

    print("\n\n======================================SUBNET SCANNING======================================\n\n")
    # Gathers and Formats Credentials
    DOMAIN_CREDENTIALS = args.wc.split(',')
    formatting_domain_creds = []
    for i in range(len(DOMAIN_CREDENTIALS)):
        DOMAIN_CREDENTIALS[i] = DOMAIN_CREDENTIALS[i].split(':')
        if len(DOMAIN_CREDENTIALS[i]) == 2:
            formatting_domain_creds.append(f"{DOMAIN_CREDENTIALS[i][0]}:{DOMAIN_CREDENTIALS[i][1]}")
    if formatting_domain_creds:
        cred_str = " | ".join(formatting_domain_creds)
        print(f"Using Windows Credentials | {cred_str}")

    LINUX_CREDENTIALS = args.lc.split(',') if args.lc is not None else None
    if LINUX_CREDENTIALS is not None:
        formatted_linux_creds = []
        for i in range(len(LINUX_CREDENTIALS)):
            LINUX_CREDENTIALS[i] = LINUX_CREDENTIALS[i].split(':')
            if len(LINUX_CREDENTIALS[i]) == 2:
                formatted_linux_creds.append(f"{LINUX_CREDENTIALS[i][0]}:{LINUX_CREDENTIALS[i][1]}")
        if formatted_linux_creds:
            cred_str = " | ".join(formatted_linux_creds)
            print(f"Using Linux Credentials | {cred_str}\n")
    
    if subnet is not None:
        subnets = [x.strip() for x in subnet.split(",")]
        
        for subnet_select in subnets:
            print(f"Scanning IPv4 subnet: {subnet_select}")
            scan_all_hosts(subnet_select)
            print(f"\n============================DETECTING OS AND POTENTIAL SERVICES FOR {subnet_select}============================\n\n")
            gather_info(subnet_select)

    if ipv6_subnet is not None:
        ipv6_subnets = [x.strip() for x in ipv6_subnet.split(",")]
        
        for ipv6_subnet_select in ipv6_subnets:
            print(f"Scanning IPv6 subnet: {ipv6_subnet_select}\n")
            scan_all_hosts(ipv6_subnet_select)
            print(f"\n============================DETECTING OS AND POTENTIAL SERVICES FOR {ipv6_subnet_select}============================\n\n")
            gather_info(ipv6_subnet_select)

    print("\n==========================ADDING INFORMATION TO ANSIBLE INVENTORY==========================\n\n")

    if RUN_WINDOWS:
        create_windows_ansible_inventory()
    if RUN_LINUX:
        find_home_directory()
        create_linux_ansible_inventory()
    print("\n==================================RECONNAISSANCE COMPLETE==================================\n\n")

if __name__ == "__main__":
    main()
