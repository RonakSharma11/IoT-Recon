from flask import Flask, render_template, request
import scapy.all
from scapy.layers.l2 import ARP, Ether
import socket
from concurrent.futures import ThreadPoolExecutor
import requests

app = Flask(__name__, template_folder='IoTtemp')  # Specify custom template folder

def get_vendor(mac):
    """Get the vendor name from the MAC address using an external API."""
    mac = mac.replace(":", "").upper()
    url = f"https://api.macvendors.com/{mac}"

    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            return "N/A"
    except requests.RequestException:
        return "N/A"

def scan_port(ip, port):
    """Scan a single port on a given IP address."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.1)  # Timeout for faster scanning
        if sock.connect_ex((ip, port)) == 0:
            return port  # Return the open port number
    return None  # Return None if the port is closed

def scan_ports(ip):
    """Scan common ports on a given IP address using multithreading."""
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389]  # Common ports to scan
    open_ports = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(lambda port: scan_port(ip, port), common_ports)

    for port in results:
        if port:
            open_ports.append(port)

    return open_ports

def scan_network(ip_range):
    """Scan the network for devices in the specified IP range and open ports."""
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = scapy.all.srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        device_info = {
            'ip': received.psrc,
            'mac': received.hwsrc,
            'vendor': get_vendor(received.hwsrc),  # Fetch vendor info
            'open_ports': scan_ports(received.psrc)  # Scan for open ports
        }
        devices.append(device_info)

    return devices

@app.route("/", methods=["GET", "POST"])
def index():
    devices = []
    if request.method == "POST":
        ip_range = request.form.get("ip_range", "192.168.1.1/24")
        devices = scan_network(ip_range)

    return render_template("IoTindex.html", devices=devices)

if __name__ == "__main__":
    app.run(debug=True)
