from scapy.layers.l2 import *
from scapy.layers.inet import *
from scapy.all import *
from scapy.layers.dot11 import *
import threading
import wifi
import psutil

from PyQt5.QtCore import pyqtSignal, QThread

class SniffThread(QThread):
    packet_received = pyqtSignal(str)
    back_button_clicked = pyqtSignal()

    def __init__(self, interface):
        super().__init__()
        self.interface = interface

    def run(self):
        try:
            sniff(iface=self.interface, prn=self.packet_callback)
        except Exception as e:
            self.packet_received.emit(f"Error: {str(e)}\n")

    def packet_callback(self, packet):
        try:
            if IP in packet and TCP in packet:
                src_ip = packet[IP].src
                dest_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dest_port = packet[TCP].dport
                payload = packet[TCP].payload

                headers = packet[TCP].sprintf("{Raw:%Raw.load%}")
                params = packet[TCP].sprintf("{Raw:%Raw.load%}")

                output = f"Packet from {src_ip}:{src_port} to {dest_ip}:{dest_port}\n"
                output += f"Headers:\n{headers}\n"
                output += f"Parameters:\n{params}\n"
                output += f"Payload (Data):\n{payload}\n\n"

                self.packet_received.emit(output)
        except Exception as e:
            self.packet_received.emit(f"Error: {str(e)}\n")

    def back_button_clicked(self):
        self.back_button_clicked.emit()
