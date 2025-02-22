import paramiko
import time
import os

# SSH server details
SSH_USER = os.getenv("SSH_USER", "root")
SSH_PASS = os.getenv("SSH_PASS", "rootpassword")
SSH_HOST = "serverSSH"
SSH_PORT = 22

# Number of iterations
ITERATIONS = 10

def generate_ssh_traffic():
    for i in range(ITERATIONS):
        try:
            print(f"Connecting to SSH server (iteration {i + 1})...")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(SSH_HOST, port=SSH_PORT, username=SSH_USER, password=SSH_PASS)
            stdin, stdout, stderr = client.exec_command(f"echo 'Hello from iteration {i + 1}'")
            print(stdout.read().decode())
            client.close()
            time.sleep(1)
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    time.sleep(10)
    generate_ssh_traffic()
