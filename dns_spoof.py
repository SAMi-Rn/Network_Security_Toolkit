# need to run arp_spoof.py with python3 before running this script as it does IP forwarding
import netfilterqueue
import subprocess


def process_packet(packet):
    print(packet)
    packet.accept()


subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
