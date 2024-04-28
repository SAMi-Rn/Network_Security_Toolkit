
# Network Security Toolkit

## Overview

This toolkit comprises three Python scripts that work in concert to perform network security tasks on Linux platforms. It includes an ARP spoofer, a DNS spoofer, and an HTTP packet sniffer. The scripts utilize the Scapy library for packet crafting and sniffing, with additional utilities for network interaction.

## Features

- **ARP Spoofing**: Manipulates ARP tables to intercept traffic between a target IP and the router.
- **DNS Spoofing**: Intercepts DNS requests and provides forged responses.
- **Packet Sniffing**: Captures HTTP packets to extract URLs and possible login credentials.

## Getting Started

First, clone the repository:

```sh
git clone https://github.com/SAMi-Rn/Network_Security_Toolkit.git
cd Network_Security_Toolkit
```
## Installation
The scripts require Scapy and NetfilterQueue. Install them using pip:
```sh
pip install scapy netfilterqueue
```
Ensure IP forwarding is enabled on your Linux machine:
```sh
echo 1 > /proc/sys/net/ipv4/ip_forward
```
To disable it post-operation:
```sh
echo 0 > /proc/sys/net/ipv4/ip_forward
```
## Usage
Each script should be run with the appropriate command-line arguments as follows:

1. **ARP Spoofing**: Target and router IP addresses are required.
2. **DNS Spoofing**: Specify the target IP address for DNS redirection.
3. **Packet Sniffing**: Designate the network interface to listen on.

#### Examples for running each script are provided in their respective sections below.
## Scripts
### 1. ARP Spoofing
```sh
# arp_spoof.py
python arp_spoof.py -t <target_ip> -r <router_ip>
```
### 2. DNS Spoofing
```sh
# dns_spoof.py
python dns_spoof.py -t <target_ip>
```
### 3. Packet Sniffing
```sh
# packet_sniffer.py
python packet_sniffer.py -i <interface_name>
```
## Notes
- The toolkit is for educational purposes and should only be used on networks where you have permission to perform these actions.
- Ensure that IP forwarding is active before running the ARP and DNS spoofers.
- Flush IP tables and stop the Apache service after running the DNS spoofer script.
