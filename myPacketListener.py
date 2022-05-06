import os
os.sys.path.append('/usr/local/lib/python2.7/site-packages')
import scapy.all as scapy
from scapy_http import http

def listen_packets(interface):

    scapy.sniff(iface=interface,store=False,prn=analyze_packets)
    #prn = callback function

def analyze_packets(packet):
    #packet.show()
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)

listen_packets("eth0")