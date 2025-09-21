from scapy.all import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import ICMPv6EchoRequest
from core.db_manager import save_alert
from core.ips_actions import block_ip

def packet_callback(pkt, rules, logger):
    try:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
        else:
            src = dst = "N/A"

        for rule in rules:
            alert_triggered = False

            # ICMP detection
            if rule.protocol == "icmp":
                if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
                    alert_triggered = True
                elif pkt.haslayer(ICMPv6EchoRequest):
                    alert_triggered = True

            # TCP detection
            if rule.protocol == "tcp" and pkt.haslayer(TCP):
                if rule.port is None or pkt[TCP].dport == rule.port:
                    alert_triggered = True

            # UDP detection
            if rule.protocol == "udp" and pkt.haslayer(UDP):
                if rule.port is None or pkt[UDP].dport == rule.port:
                    alert_triggered = True

            if alert_triggered:
                msg = f"[ALERT] {rule.msg or 'Suspicious Packet'} - {pkt.summary()} - Severity: {rule.severity}"
                logger.info(msg)
                print(msg)

                # Save to DB
                port = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport if pkt.haslayer(UDP) else None
                save_alert(src, dst, rule.protocol, port, rule.severity, rule.msg)

                # IPS Action: block high severity
                if rule.severity.lower() == "high":
                    block_ip(src)

    except Exception as e:
        logger.error(f"Error processing packet: {e}")
