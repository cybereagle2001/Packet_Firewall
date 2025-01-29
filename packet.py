from scapy.all import *

class Packet:
    def __init__(self, packet):
        """
        Initialise un objet Packet avec un paquet Scapy.
        :param packet: Paquet réseau capturé par Scapy.
        """
        self.packet = packet

    def get_protocol(self):
        """
        Retourne le protocole du paquet (TCP, UDP, ICMP, ou autre).
        """
        if self.packet.haslayer(TCP):
            return "TCP"
        elif self.packet.haslayer(UDP):
            return "UDP"
        elif self.packet.haslayer(ICMP):
            return "ICMP"
        else:
            return "Autre"

    def get_ip_info(self):
        """
        Retourne les adresses IP source et destination.
        """
        if self.packet.haslayer(IP):
            return self.packet[IP].src, self.packet[IP].dst
        return None, None

    def get_port_info(self):
        """
        Retourne les ports source et destination (si applicable).
        """
        if self.packet.haslayer(TCP):
            return self.packet[TCP].sport, self.packet[TCP].dport
        elif self.packet.haslayer(UDP):
            return self.packet[UDP].sport, self.packet[UDP].dport
        return None, None

    def get_summary(self):
        """
        Retourne un résumé du paquet.
        """
        return self.packet.summary()
