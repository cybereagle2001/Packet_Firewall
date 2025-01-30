from scapy.all import *
from packet import *

class Firewall:
    def __init__(self, interface="eth0"):
        """
        Initialize the Firewall with a network interface and a log file.
        :param interface: Network interface to listen on (default "eth0").
        """
        self.interface = interface
        self.packet_summaries = []  # List to store packet summaries

    def packet_callback(self, packet):
        """
        Callback function to process each captured packet.
        :param packet: Network packet captured by Scapy.
        """
        # Create a Packet object to encapsulate the packet
        packet_obj = Packet(packet)

        # Analyze the packet using the methods of the Packet class
        self.analyze_packet(packet_obj)

    def analyze_packet(self, packet_obj):
        """
        Analyze a packet using the methods of the Packet class.
        :param packet_obj: Packet object to analyze.
        """
        # Use the methods of the Packet class to extract information
        protocol = packet_obj.get_protocol()
        ip_src, ip_dst = packet_obj.get_ip_info()
        port_src, port_dst = packet_obj.get_port_info()

        # Create a summary of the packet
        summary = f"Protocol: {protocol}, Source IP: {ip_src}, Destination IP: {ip_dst}"
        if port_src and port_dst:
            summary += f", Source Port: {port_src}, Destination Port: {port_dst}"

        # Store the summary in the list
        self.packet_summaries.append(summary)

    def get_packet_summaries(self):
        """
        Retrieve the list of packet summaries.
        :return: List of packet summaries.
        """
        return self.packet_summaries

    def start_capture(self):
        """
        Start capturing packets on the network interface.
        """
        print(f"Capturing on interface {self.interface}...")
        sniff(iface=self.interface, prn=self.packet_callback)
