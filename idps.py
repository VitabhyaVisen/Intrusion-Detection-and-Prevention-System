from core.rule_engine import load_rules
from core.logger import setup_logger
from core.db_manager import init_db
from core.packet_handler import packet_callback
from scapy.all import sniff

def main():
    print("[*] Starting IDS/IPS Phase 2...")

    # Load rules
    rules = load_rules("rules")
    print(f"[*] Loaded {len(rules)} rules")

    # Setup logger
    logger = setup_logger()

    # Initialize DB
    init_db()

    # Network interface
    interface = "eth1"  # Replace with your interface
    print(f"[*] Sniffing on interface: {interface}")

    # Start sniffing
    sniff(prn=lambda pkt: packet_callback(pkt, rules, logger),
          store=0, iface=interface)

if __name__ == "__main__":
    main()
