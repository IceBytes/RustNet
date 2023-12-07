from scapy.layers.l2 import *
from scapy.layers.inet import *
from scapy.all import *
from scapy.layers.dot11 import *
import wifi
import psutil
from ipaddress import *
import netifaces

from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QComboBox, QTextEdit, QInputDialog, QMessageBox
from PyQt5.QtCore import Qt, QPropertyAnimation, QEasingCurve
import psutil
import wifi
from jamming_page import JammingThread
from sniffing_page import SniffThread
from functions import interfaces_list, devices_list
from qdarkstyle import load_stylesheet_pyqt5
import sys

class RustNetApp(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("RustNet - Manage your network")
        self.setGeometry(100, 100, 800, 600)

        self.current_interface = ""
        self.connected_network = ""
        self.router_ip = ""
        self.broadcast_addr = ""
        self.sniff_thread = None
        self.jamming_thread = None

        self.setup_ui()

    def setup_ui(self):
        self.central_layout = QVBoxLayout(self)

        splash_label = QLabel("RustNet", self)
        splash_label.setAlignment(Qt.AlignCenter)
        splash_label.setStyleSheet("font-size: 36px; font-weight: bold; color: #3498db")  
        self.central_layout.addWidget(splash_label)

        description = QLabel("Let's manage your network", self)
        description.setAlignment(Qt.AlignBottom | Qt.AlignCenter)
        description.setStyleSheet("font-size: 20px; color: #2ecc71")  
        self.central_layout.addWidget(description)

        start_button = QPushButton("Start", self)
        start_button.clicked.connect(self.show_interface_screen)
        start_button.setStyleSheet("background-color: #e74c3c; color: #fff")  
        self.central_layout.addWidget(start_button)

        self.setStyleSheet(load_stylesheet_pyqt5())

        self.apply_animations(splash_label)
        self.apply_animations(description)
        self.apply_animations(start_button)

    def apply_animations(self, widget):
        fade_in_animation = QPropertyAnimation(widget, b"opacity")
        fade_in_animation.setStartValue(0.0)
        fade_in_animation.setEndValue(1.0)
        fade_in_animation.setDuration(1000)
        fade_in_animation.setEasingCurve(QEasingCurve.OutBack)
        fade_in_animation.start()

    def show_interface_screen(self):
        self.clear_layout()
        interface_layout = QVBoxLayout()

        interface_label = QLabel("Choose Interface:", self)
        interface_layout.addWidget(interface_label)

        interfaces = self.interfaces_list()
        interface_combobox = QComboBox(self)
        interface_combobox.addItems(interfaces)
        interface_layout.addWidget(interface_combobox)

        router_ip, ok1 = QInputDialog.getText(self, 'Input', 'Enter Router IP:')

        if ok1:
            self.router_ip = router_ip

            start_button = QPushButton("Sniffing", self)
            start_button.clicked.connect(lambda: self.show_sniff_screen(interface_combobox.currentText()))
            interface_layout.addWidget(start_button)

            jamming_button = QPushButton("Jamming", self)
            jamming_button.clicked.connect(lambda: self.show_jamming_screen(interface_combobox.currentText()))
            interface_layout.addWidget(jamming_button)

            self.central_layout.addLayout(interface_layout)
        else:
            QMessageBox.warning(self, "Input Error", "Invalid input for Router IP or Broadcast Address", QMessageBox.Ok)

    def show_sniff_screen(self, interface):
        self.clear_layout()
        sniff_layout = QVBoxLayout()

        self.sniff_text = QTextEdit(self)
        self.sniff_text.setReadOnly(True)
        sniff_layout.addWidget(self.sniff_text)

        buttons_layout = QVBoxLayout()

        start_sniff_button = QPushButton("Start Sniff", self)
        start_sniff_button.clicked.connect(lambda: self.start_sniff(interface))
        start_sniff_button.setStyleSheet("background-color: #3498db; color: #fff") 
        buttons_layout.addWidget(start_sniff_button)

        stop_sniff_button = QPushButton("Stop Sniff", self)
        stop_sniff_button.clicked.connect(self.stop_sniff)
        stop_sniff_button.setStyleSheet("background-color: #e74c3c; color: #fff")  
        buttons_layout.addWidget(stop_sniff_button)

        sniff_layout.addLayout(buttons_layout)

        self.central_layout.addLayout(sniff_layout)

    def show_jamming_screen(self, interface):
        self.clear_layout()
        jamming_layout = QVBoxLayout()

        self.jamming_text = QTextEdit(self)
        self.jamming_text.setReadOnly(True)
        jamming_layout.addWidget(self.jamming_text)

        networks_label = QLabel("Choose Network to Jam:", self)
        jamming_layout.addWidget(networks_label)

        networks = self.devices_list(interface)
        networks_combobox = QComboBox(self)
        for network in networks:
            networks_combobox.addItem(f"{network[0]} - {network[1]}")
        jamming_layout.addWidget(networks_combobox)

        buttons_layout = QVBoxLayout()

        connect_button = QPushButton("Connect to Network", self)
        connect_button.clicked.connect(lambda: self.connect_to_network(networks_combobox.currentText(), interface))
        connect_button.setStyleSheet("background-color: #3498db; color: #fff")  
        buttons_layout.addWidget(connect_button)

        start_jamming_button = QPushButton("Start Jamming", self)
        start_jamming_button.clicked.connect(lambda: self.start_jamming(interface))
        start_jamming_button.setStyleSheet("background-color: #27ae60; color: #fff")  
        buttons_layout.addWidget(start_jamming_button)

        stop_jamming_button = QPushButton("Stop Jamming", self)
        stop_jamming_button.clicked.connect(self.stop_jamming)
        stop_jamming_button.setStyleSheet("background-color: #e74c3c; color: #fff")  
        buttons_layout.addWidget(stop_jamming_button)

        jamming_layout.addLayout(buttons_layout)

        self.central_layout.addLayout(jamming_layout)

        if self.jamming_thread:
            self.jamming_thread.jamming_output.connect(self.jamming_text.append)

    def connect_to_network(self, network_info, interface):
        selected_network = network_info.split(" - ")[0]
        if self.is_network_connected(interface, selected_network):
            self.connected_network = selected_network
            QMessageBox.information(self, "Connected", f"Connected to network: {selected_network}", QMessageBox.Ok)
        else:
            QMessageBox.warning(self, "Not Connected", "You must connect to the network first.", QMessageBox.Ok)

    def start_sniff(self, interface):
        self.sniff_text.clear()
        self.sniff_thread = SniffThread(interface)
        self.sniff_thread.packet_received.connect(self.handle_packet_received)
        self.sniff_thread.start()

    def handle_packet_received(self, packet):
        self.sniff_text.append(packet)

    def stop_sniff(self):
        if self.sniff_thread and self.sniff_thread.isRunning():
            self.sniff_thread.terminate()
            self.sniff_thread.wait()

    def start_jamming(self, interface):
        if self.connected_network:
            self.jamming_text.clear()
            self.jamming_thread = JammingThread(interface, self.connected_network, self.router_ip)
            self.jamming_thread.jamming_output.connect(self.jamming_text.append)
            self.jamming_thread.start()
        else:
            QMessageBox.warning(self, "Not Connected", "You must connect to a network before starting jamming.", QMessageBox.Ok)

    def stop_jamming(self):
        if self.jamming_thread and self.jamming_thread.isRunning():
            self.jamming_thread.stop_jamming()
            self.jamming_thread.wait()

    def clear_layout(self):
        while self.central_layout.count() > 0:
            item = self.central_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                self.clear_sub_layout(item.layout())

    def clear_sub_layout(self, layout):
        while layout.count() > 0:
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                self.clear_sub_layout(item.layout())

    def interfaces_list(self):
        l = []
        interfaces = psutil.net_if_addrs()

        for interface, addrs in interfaces.items():
            l.append(interface)
        return l

    def devices_list(self, interface: str):
        l = []
        networks = wifi.Cell.all(interface)
        for network in networks:
            l.append((network.ssid, network.address, network.encryption_type, network.frequency, network.signal))
        return l

    def is_network_connected(self, interface, network_name):
        try:
            networks = wifi.Cell.all(interface)
            for network in networks:
                if network.ssid == network_name:
                    return True
            return False
        except Exception as e:
            print(f"Error checking network connection: {e}")
            return False