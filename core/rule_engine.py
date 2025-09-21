import os
import re

class Rule:
    def __init__(self, protocol, port=None, msg=None, severity="low"):
        self.protocol = protocol
        self.port = port
        self.msg = msg
        self.severity = severity

def parse_rule(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    protocol = None
    port = None
    msg = None
    severity = "low"

    lower_line = line.lower()
    if "icmp" in lower_line:
        protocol = "icmp"
    elif "tcp" in lower_line:
        protocol = "tcp"
    elif "udp" in lower_line:
        protocol = "udp"

    # Extract port (basic)
    match = re.search(r"\b(\d{1,5})\b", line)
    if match:
        port = int(match.group(1))

    # Extract message
    match_msg = re.search(r'msg\s*:\s*"(.*?)"', line)
    if match_msg:
        msg = match_msg.group(1)

    # Extract severity
    match_sev = re.search(r"severity\s*:\s*(\w+)", line)
    if match_sev:
        severity = match_sev.group(1)

    return Rule(protocol, port, msg, severity)

def load_rules(rules_dir="rules"):
    rules = []
    for file in os.listdir(rules_dir):
        if file.endswith(".rules"):
            with open(os.path.join(rules_dir, file), "r") as f:
                for line in f:
                    rule_obj = parse_rule(line)
                    if rule_obj:
                        rules.append(rule_obj)
    return rules
