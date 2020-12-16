#! /usr/bin/python
import scapy
import os
import json
from scapy.all import *
from scapy.utils import PcapReader
import numpy as np

import argparse
import time

parser = argparse.ArgumentParser(description='Process pcap file and split into subfile. NOTE: Only output first sub pcap.')
parser.add_argument('-i', '--input', action='store', dest="pcap_in", default=None,
                    required=True, help="Input Pcap File.")
parser.add_argument('-o', '--output', action='store', dest="pcap_out", default=None,
                    required=True, help="Output Pcap File.")
args = parser.parse_args()

pcap_input = args.pcap_in
pcap_output = args.pcap_out

cnt = 0
with open(pcap_output, 'wb') as fp:
    for packet in PcapReader( pcap_input):
        cnt += 1
    	if packet.haslayer("IP"):
    		ipv4_src = packet['IP'].src
    		ipv4_dst = packet['IP'].dst
    		sport = 0
    		dport = 0
    		protocol = 0
    		if packet.haslayer("TCP"):
    			protocol = 6
    			sport = packet['TCP'].sport
    			dport = packet['TCP'].dport
    		if packet.haslayer("UDP"):
    			protocol = 17
    			sport = packet['UDP'].sport
    			dport = packet['UDP'].dport
                pkt_len = len(packet)
                data = b''
                #print (ipv4_src, ipv4_dst, sport, dport, protocol)
    		five_tuple = (socket.inet_aton(ipv4_src), 
                                  struct.pack('!H',sport), 
                                  socket.inet_aton(ipv4_dst), 
                                  struct.pack('!H',dport),
                                  struct.pack('b',protocol) )
                                  #struct.pack('!H',pkt_len))
                for da in five_tuple:
                    data += da
                fp.write(data)
        if cnt % 30000 ==0:
            print("Process %d packets...." % cnt)
