import os
import paramiko
import socket

# 1. Define the remote host as it appears in your ~/.ssh/config file
REMOTE_HOST_ALIAS = "new-test-deb12.teleport.local"  # Replace with your actual host alias

# 2. Load and parse the SSH configuration file
ssh_config_path = os.path.expanduser("ssh.cfg")
ssh_config = paramiko.SSHConfig()
try:
    with open(ssh_config_path) as f:
        ssh_config.parse(f)
except FileNotFoundError:
    print(f"Error: SSH config file not found at {ssh_config_path}")
    exit(1)

# 3. Look up configuration for the specific host
host_config = ssh_config.lookup(REMOTE_HOST_ALIAS)

# 4. Handle ProxyCommand for Teleport (if applicable)
proxy = None
if 'proxycommand' in host_config:
    proxy_command_str = host_config['proxycommand']
    # Paramiko's ProxyCommand handles the execution
    proxy = paramiko.ProxyCommand(proxy_command_str)

# 5. Create the SSH client
client = paramiko.SSHClient()
# Automatically add the host key (use with caution, or pre-load known hosts)
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    # Extract parameters from the config lookup
    hostname = host_config.get('hostname', REMOTE_HOST_ALIAS)
    username = "ccdc"
    port = int(host_config.get('port', 22))
    
    # Handle identity file (private key) if specified
    key_filename = host_config.get('identityfile')
    cert_filename = host_config.get('certificatefile')
    print(key_filename)
    print(cert_filename)
    if key_filename:
        key_filename = key_filename[0]

    try:
        priv_key = paramiko.RSAKey.from_private_key_file(key_filename)
    except paramiko.SSHException:
        priv_key = paramiko.Ed25519Key.from_private_key_file(key_filename)

    # 2. Manually load the certificate
    if cert_filename:
        with open(cert_filename, 'r') as f:
            cert_content = f.read().strip()
            priv_key.load_certificate(cert_content)

    print(f"Connecting to {username}@{hostname}:{port}...")

    client.connect(
        hostname=hostname,
        port=port,
        username=username,
        pkey=priv_key,
        sock=proxy,
        timeout=10,
        allow_agent=False,
        look_for_keys=False
    )
    
    print("Connection established successfully!")
    stdin, stdout, stderr = client.exec_command('pwd')
    print(stdout.read().decode())

except paramiko.SSHException as e:
    print(f"SSH connection failed: {e}")
except socket.timeout:
    print("Connection timed out.")
except Exception as e:
    print(f"An error occurred: {e}")

finally:
    # 8. Close the connection
    if client:
        client.close()
        print("Connection closed.")
