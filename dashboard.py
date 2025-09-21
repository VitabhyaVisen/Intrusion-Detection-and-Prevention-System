import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue
from core.db_manager import init_db, save_alert
from core.ips_actions import block_ip, unblock_ip
from core.rule_engine import load_rules
from core.logger import setup_logger
from core.packet_handler import packet_callback
from scapy.all import sniff

# Queue to communicate between sniffing thread and GUI
alert_queue = queue.Queue()

# IDS packet callback wrapper for GUI
def gui_packet_callback(pkt, rules, logger):
    packet_callback(pkt, rules, logger)
    # Put alert info in queue for GUI display
    src = pkt[0][1].src if pkt.haslayer("IP") else "N/A"
    dst = pkt[0][1].dst if pkt.haslayer("IP") else "N/A"
    proto = "ICMP" if pkt.haslayer("ICMP") else "TCP" if pkt.haslayer("TCP") else "UDP" if pkt.haslayer("UDP") else "OTHER"
    severity = "low"  # default
    # Try to get severity from rules
    for rule in rules:
        if rule.protocol.lower() == proto.lower():
            severity = rule.severity
            break
    msg = f"{proto} packet from {src} -> {dst}"
    alert_queue.put((src, dst, proto, msg, severity))

# IDS sniffing in a separate thread
def start_sniff(interface, rules, logger):
    sniff(prn=lambda pkt: gui_packet_callback(pkt, rules, logger),
          store=0, iface=interface)

# GUI Class
class IDPSDashboard(tk.Tk):
    def __init__(self, rules, interface="eth1"):
        super().__init__()
        self.title("IDS/IPS Dashboard")
        self.geometry("950x500")
        self.rules = rules
        self.interface = interface
        self.logger = setup_logger()
        self.init_gui()
        self.start_ids_thread()
        self.update_alerts()

    def init_gui(self):
        # Treeview for live alerts
        columns = ("src_ip", "dst_ip", "protocol", "severity", "message")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, anchor="center")
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Buttons for IPS actions
        btn_frame = tk.Frame(self)
        btn_frame.pack(fill=tk.X)
        tk.Button(btn_frame, text="Block IP", command=self.block_selected_ip).pack(side=tk.LEFT, padx=10, pady=5)
        tk.Button(btn_frame, text="Unblock IP", command=self.unblock_selected_ip).pack(side=tk.LEFT, padx=10, pady=5)

    def start_ids_thread(self):
        threading.Thread(target=start_sniff, args=(self.interface, self.rules, self.logger), daemon=True).start()

    def update_alerts(self):
        while not alert_queue.empty():
            src, dst, proto, msg, severity = alert_queue.get()

            # Set color based on severity
            if severity.lower() == "low":
                color = "#90EE90"  # Light green
            elif severity.lower() == "medium":
                color = "#FFA500"  # Orange
            elif severity.lower() == "high":
                color = "#FF6347"  # Red
            else:
                color = "white"

            # Create a unique tag for this row to keep color fixed
            tag_name = f"{src}_{dst}_{proto}_{self.tree.get_children().__len__()}"
            self.tree.insert("", tk.END, values=(src, dst, proto, severity, msg), tags=(tag_name,))
            self.tree.tag_configure(tag_name, background=color)

        self.after(500, self.update_alerts)

    def block_selected_ip(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "No alert selected!")
            return
        for item in selected:
            src_ip = self.tree.item(item)["values"][0]
            block_ip(src_ip)
            messagebox.showinfo("Blocked", f"Blocked IP: {src_ip}")

    def unblock_selected_ip(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "No alert selected!")
            return
        for item in selected:
            src_ip = self.tree.item(item)["values"][0]
            unblock_ip(src_ip)
            messagebox.showinfo("Unblocked", f"Unblocked IP: {src_ip}")

# Run dashboard
if __name__ == "__main__":
    init_db()
    rules = load_rules("rules")
    app = IDPSDashboard(rules)
    app.mainloop()
