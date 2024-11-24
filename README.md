# RogueAP

This repository contains scripts to create an access points using Python and Scapy, and to configure a hostapd access point to bypass [Snappy](https://github.com/SpiderLabs/snappy/tree/main) verification.  

## Table of Contents  
- [hostapdCreation.py](#hostapdcreationpy)  
  - [Description](#description)  
  - [Requirements](#requirements)  
  - [Example Usage](#example-usage)  
- [ap.py](#appy)  
  - [Description](#description-1)  
  - [Requirements](#requirements-1)  
  - [Example Usage](#example-usage-1)  

---

## hostapdCreation.py  

### Description  
This script takes a `.pcap` file containing at least one beacon frame as input. From that beacon frame, it generates a `hostapd` configuration file that bypasses the Snappy verification.  

### Requirements

```bash
sudo apt install hostapd
sudo apt install dnsmasq

pip install scapy
```

### Example Usage  
```bash
sudo python3 hostapdCreation.py pcap/legitimate.pcap wlan0
```


1. To give internet access to the cients, configure dnsmasq.conf file:
```bash
nano dnsmasq.conf
```
Add the following content:

```txt
interface=wlan0
dhcp-range=10.0.0.100,10.0.0.250,255.255.255.0,12h 
dhcp-option=3,10.0.0.1 
dhcp-option=6,10.0.0.1 
server=8.8.8.8 
log-queries 
log-dhcp 
listen-address=127.0.0.1
```
2. Set up the network interface and enable forwarding:
```bash
sudo ifconfig wlan0 10.0.0.1/24 
sudo sysctl -w net.ipv4.ip_forward=1
```
3. Configure iptables to forward traffic to get internet access for the clients:
```bash
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```
4. Start dnsmasq:
```bash
sudo dnsmasq -C dnsmasq.conf -d
```

## ap.py

### Description
This script create an access point in python using the library [Scapy](https://scapy.net/).

### Requirements
Install the required library:

```bash
sudo apt install hostapd
sudo apt install dnsmasq

pip install scapy
```

### Example usage

1. Preapre the network interface (Channel and MAC address need to be changed to your configuration):
```bash
sudo airmon-ng check kill
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set dev wlan0 address 28:87:ba:c0:43:38
sudo ip link set wlan0 up
sudo iw dev wlan0 set channel 11
```

2. Run the script:
```bash
sudo python3 ap.py pcap/legitimate.pcap wlan0
```
3. To give internet access to the cients, configure dnsmasq.conf file:

Create a dnsmasq.conf file:
```bash
nano dnsmasq.conf
```

Add the following content:

    interface=wlan0
    dhcp-range=10.0.0.100,10.0.0.250,255.255.255.0,12h 
    dhcp-option=3,10.0.0.1 
    dhcp-option=6,10.0.0.1 
    server=8.8.8.8 
    log-queries 
    log-dhcp 
    listen-address=127.0.0.1

4. Enable IP forwarding and configure iptables:
```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1

sudo iptables -F
sudo iptables -t nat -F
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

sudo iptables -A FORWARD -i at0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o at0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```
    
5. Start dnsmasq:
```bash
sudo dnsmasq -C dnsmasq.conf -d
```