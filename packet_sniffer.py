import scapy.all as scapy


def sniff(interface):
    # store=0 is used to not store the packets in memory
    # prn is the callback function that will be called for each packet sniffed
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def process_packet(packet):
    print(packet.show())


sniff("en0")
