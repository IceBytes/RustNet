import wifi
import psutil

def interfaces_list():
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())

def devices_list(interface: str):
    networks = wifi.Cell.all(interface)
    return [(network.ssid, network.address, network.encryption_type, network.frequency, network.signal) for network in networks]
