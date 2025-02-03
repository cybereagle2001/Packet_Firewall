from scapy.all import *
from packet import *
import json

class Firewall:
    def __init__(self, interface="eth0",log_file="packet_log.txt"):
        """
        Initialize the Firewall with a network interface, policies, and user management.
        :param interface: Network interface to listen on (default "eth0").
        """
        self.interface = interface
        self.packet_summaries = []  # List to store packet summaries
        self.policies = self.load_policies()  # List of firewall policies (rules)
        self.allowed_users = []  # List of authorized users

    def export_policies(self):
        """Export the current firewall policies to policies.log."""
        with open("policies.log", "w") as file:
            json.dump(self.policies, file, indent=4)

    def load_policies(self):
        """Load firewall policies from policies.log if it exists."""
        try:
            with open("policies.log", "r") as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def add_policy(self, policy):
        """Add a new firewall policy (block IP, port, or protocol)."""
        if policy not in self.policies:
            self.policies.append(policy)
            self.export_policies()
            print(f"✅ Policy added: {policy}")
        else:
            print(f"⚠️ Policy already exists: {policy}")

    def remove_policy(self, policy):
        """Remove an existing firewall policy."""
        if policy in self.policies:
            self.policies.remove(policy)
            self.export_policies()
            print(f"❌ Policy removed: {policy}")
        else:
            print(f"⚠️ Policy not found: {policy}")


    def is_packet_allowed(self, packet_obj):
        """Check if a packet matches any policy (blocking rule)."""
        protocol = packet_obj.get_protocol()
        ip_src, ip_dst = packet_obj.get_ip_info()
        port_src, port_dst = packet_obj.get_port_info()

        for policy in self.policies:
            if policy in [protocol, ip_src, ip_dst, str(port_src), str(port_dst)]:
                return False  # Block packet
        return True  # Allow packet

    def packet_callback(self, packet):
        """
        Callback function to process each captured packet.
        :param packet: Network packet captured by Scapy.
        """
        packet_obj = Packet(packet)

        # Apply firewall policies
        if not self.is_packet_allowed(packet_obj):
            print(f"❌ Packet Blocked: {packet_obj.get_ip_info()}")

        self.analyze_packet(packet_obj)

    def analyze_packet(self, packet_obj):
        """Analyze a packet and store its details."""
        protocol = packet_obj.get_protocol()
        ip_src, ip_dst = packet_obj.get_ip_info()
        port_src, port_dst = packet_obj.get_port_info()


        summary = f"Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, Protocol: {protocol}, Source IP: {ip_src}, Destination IP: {ip_dst}"
        if port_src and port_dst:
            summary += f", Source Port: {port_src}, Destination Port: {port_dst}"
        else:
            summary += f", Source Port: N/A, Destination Port: N/A"
        
        if self.is_packet_allowed(packet_obj):
            summary+= f", Action: Allow"
        else:
            summary+= f", Action: Deny"

        self.packet_summaries.append(summary)

    def get_packet_summaries(self):
        """Retrieve the list of packet summaries."""
        return self.packet_summaries
    
    def log_packet(self, packet_obj):
        """
        Enregistre les informations du paquet dans le fichier journal.
        :param packet_obj: Objet Packet à journaliser.
        """
        # Utilise la méthode get_summary() de la classe Packet pour journaliser le paquet
        logging.info(packet_obj.get_summary())

    def start_capture(self):
        """Start capturing packets on the network interface."""
        print(f"🚀 Capturing on interface {self.interface}...")
        sniff(iface=self.interface, prn=self.packet_callback)
