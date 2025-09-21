import subprocess

def block_ip(ip):
    print(f"[*] Blocking IP: {ip}")
    subprocess.call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

def unblock_ip(ip):
    print(f"[*] Unblocking IP: {ip}")
    subprocess.call(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
