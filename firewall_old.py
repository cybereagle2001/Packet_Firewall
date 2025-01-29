from scapy.all import *
from packet import *

class Firewall:
    def __init__(self, interface="eth0"):
        """
        Initialise le Firewall avec une interface réseau et un fichier de logs.
        :param interface: Interface réseau à écouter (par défaut "eth0").
        """
        self.interface = interface
 
    def packet_callback(self, packet):
        """
        Fonction de rappel pour traiter chaque paquet capturé.
        :param packet: Paquet réseau capturé par Scapy.
        """
        # Crée un objet Packet pour encapsuler le paquet
        packet_obj = Packet(packet)

        # Analyse le paquet en utilisant les méthodes de la classe Packet
        self.analyze_packet(packet_obj)

    def analyze_packet(self, packet_obj):
        """
        Analyse un paquet en utilisant les méthodes de la classe Packet.
        :param packet_obj: Objet Packet à analyser.
        """
        # Utilise les méthodes de la classe Packet pour extraire les informations
        protocol = packet_obj.get_protocol()
        ip_src, ip_dst = packet_obj.get_ip_info()
        port_src, port_dst = packet_obj.get_port_info()

        # Affiche les informations du paquet
        print(f"Protocole : {protocol}")
        print(f"IP Source : {ip_src}, IP Destination : {ip_dst}")
        if port_src and port_dst:
            print(f"Port Source : {port_src}, Port Destination : {port_dst}")

    def start_capture(self):
        """
        Démarre la capture des paquets sur l'interface réseau.
        :param count: Nombre de paquets à capturer (par défaut 10).
        """
        print(f"Capture en cours sur l'interface {self.interface}...")
        sniff(iface=self.interface, prn=self.packet_callback)

if __name__ == "__main__":
    # Crée une instance de Firewall
    firewall = Firewall(interface="eth0")

    # Démarre la capture des paquets
    firewall.start_capture()
