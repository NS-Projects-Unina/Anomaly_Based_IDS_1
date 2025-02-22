import time
import subprocess

def perform_traceroute(target):
    try:
        print(f"Performing traceroute to {target}...")
        result = subprocess.run(["traceroute", target], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    time.sleep(20)
    target = "serverDNS"
    perform_traceroute(target)
