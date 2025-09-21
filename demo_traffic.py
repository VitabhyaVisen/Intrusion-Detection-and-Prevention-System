import os
import time
import subprocess

def generate_icmp():
    print("[*] Generating ICMP traffic (ping)...")
    subprocess.call(["ping", "-c", "3", "-4", "8.8.8.8"])

def generate_http():
    print("[*] Generating HTTP traffic...")
    subprocess.call(["curl", "-s", "http://example.com"])

def generate_https():
    print("[*] Generating HTTPS traffic...")
    subprocess.call(["curl", "-s", "https://example.com"])

def generate_ssh():
    print("[*] Generating SSH traffic...")
    # Attempt SSH to localhost (requires ssh server running)
    subprocess.call(["ssh", "-o", "StrictHostKeyChecking=no", "localhost", "exit"])

def generate_dns():
    print("[*] Generating DNS traffic...")
    subprocess.call(["nslookup", "example.com"])

def generate_dhcp():
    print("[*] Generating DHCP traffic...")
    # Renew DHCP lease (requires sudo)
    subprocess.call(["sudo", "dhclient", "-v", "-r"])
    subprocess.call(["sudo", "dhclient", "-v"])

def generate_ftp():
    print("[*] Generating FTP traffic...")
    # Requires ftp server or localhost test
    subprocess.call(["ftp", "-n", "localhost"], stdin=subprocess.PIPE)

def main():
    print("[*] Starting traffic demo for IDS...")
    time.sleep(2)

    generate_icmp()
    time.sleep(1)

    generate_http()
    generate_https()
    time.sleep(1)

    generate_ssh()
    time.sleep(1)

    generate_dns()
    time.sleep(1)

    generate_dhcp()
    time.sleep(1)

    # Optional FTP test if server available
    # generate_ftp()

    print("[*] Traffic demo completed. Check IDS alerts.log or console.")

if __name__ == "__main__":
    main()
