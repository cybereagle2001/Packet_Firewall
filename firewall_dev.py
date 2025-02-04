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
        """
        Check if a packet matches any policy (blocking rule).
        :param packet_obj: Packet object to check.
        :return: True if the packet is allowed, False if it is denied."""

        protocol = packet_obj.get_protocol()
        ip_src, ip_dst = packet_obj.get_ip_info()
        port_src, port_dst = packet_obj.get_port_info()

        for policy in reversed(self.policies):
            # Split the policy into its components
            policy_parts = policy.split(",")
            policy_id, policy_protocol, policy_action, policy_src_ip, policy_dst_ip, policy_src_port, policy_dst_port = policy_parts

        # Check if the packet matches the policy
            if ((policy_src_ip == ip_src or policy_src_ip == "any") and
            (policy_dst_ip == ip_dst or policy_dst_ip == "any") and
            (policy_src_port == str(port_src) or policy_src_port == "any") and
            (policy_dst_port == str(port_dst) or policy_dst_port == "any")):

                # If the policy action is "Deny", block the packet
                if policy_action == "Deny":
                    return False
                # If the policy action is "Allow", allow the packet
                elif policy_action == "Allow":
                    return True

            else:
                return False

    def packet_callback(self, packet):
        """
        Callback function to process each captured packet.
        :param packet: Network packet captured by Scapy.
        """
        packet_obj = Packet(packet)
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
            summary += f", Source Port: ANY, Destination Port: ANY"

        if self.is_packet_allowed(packet_obj):
            summary+= f", Action: Allow"
        else:
            summary+= f", Action: Deny"
            print(f"❌ Packet Blocked: {packet_obj.get_ip_info()}")
            if packet_obj.packet.haslayer(IP):
                packet_obj.packet[IP].ttl = 0
            else:
                print(f"❌ LAYER 2 PACKET")

        self.packet_summaries.append(summary)
        self.log_packet(packet_obj,summary)

    def get_packet_summaries(self):
        """Retrieve the list of packet summaries."""
        return self.packet_summaries

    def log_packet(self, packet_obj,summary):
        """
        Enregistre les informations du paquet dans le fichier journal.
        :param packet_obj: Objet Packet à journaliser.
        """
        with open("packet_log.txt", "a") as file:
            summary = summary+'\n'
            file.write(summary)

    def start_capture(self):
        """Start capturing packets on the network interface."""
        print(f"🚀 Capturing on interface {self.interface}...")
        sniff(iface=self.interface, prn=self.packet_callback)%
➜  IMEDRA_FW git:(main) ✗ cat firewall_perfect.py
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
        """
        Check if a packet matches any policy (blocking rule).
        :param packet_obj: Packet object to check.
        :return: True if the packet is allowed, False if it is denied."""

        protocol = packet_obj.get_protocol()
        ip_src, ip_dst = packet_obj.get_ip_info()
        port_src, port_dst = packet_obj.get_port_info()

        for policy in reversed(self.policies):
            # Split the policy into its components
            policy_parts = policy.split(",")
            policy_id, policy_protocol, policy_action, policy_src_ip, policy_dst_ip, policy_src_port, policy_dst_port = policy_parts

        # Check if the packet matches the policy
            if ((policy_src_ip == ip_src or policy_src_ip == "any") and
            (policy_dst_ip == ip_dst or policy_dst_ip == "any") and
            (policy_src_port == str(port_src) or policy_src_port == "any") and
            (policy_dst_port == str(port_dst) or policy_dst_port == "any")):

                # If the policy action is "Deny", block the packet
                if policy_action == "Deny":
                    return False
                # If the policy action is "Allow", allow the packet
                elif policy_action == "Allow":
                    return True

            else:
                return False

    def packet_callback(self, packet):
        """
        Callback function to process each captured packet.
        :param packet: Network packet captured by Scapy.
        """
        packet_obj = Packet(packet)
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
            summary += f", Source Port: ANY, Destination Port: ANY"

        if self.is_packet_allowed(packet_obj):
            summary+= f", Action: Allow"
        else:
            summary+= f", Action: Deny"
            print(f"❌ Packet Blocked: {packet_obj.get_ip_info()}")
            if packet_obj.packet.haslayer(IP):
                packet_obj.packet[IP].ttl = 0
            else:
                print(f"❌ LAYER 2 PACKET")

        self.packet_summaries.append(summary)
        self.log_packet(packet_obj,summary)

    def get_packet_summaries(self):
        """Retrieve the list of packet summaries."""
        return self.packet_summaries

    def log_packet(self, packet_obj,summary):
        """
        Enregistre les informations du paquet dans le fichier journal.
        :param packet_obj: Objet Packet à journaliser.
        """
        with open("packet_log.txt", "a") as file:
            summary = summary+'\n'
            file.write(summary)

    def start_capture(self):
        """Start capturing packets on the network interface."""
        print(f"🚀 Capturing on interface {self.interface}...")
        sniff(iface=self.interface, prn=self.packet_callback)
