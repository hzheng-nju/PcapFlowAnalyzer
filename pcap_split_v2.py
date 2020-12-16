#! /usr/bin/python
# -*- coding:utf8 -*-
import os
import scapy
from scapy.all import *
from scapy.utils import PcapReader
import argparse
import time

parser = argparse.ArgumentParser(description='Process pcap file and split into subfile. NOTE: Only output first sub pcap.')
parser.add_argument('-t', '--type', action='store', dest="split_type", default=1,
                    type=int, choices=(0, 1), required=False,
                    help="What split type do you want: [0: time, 1: pkt_num]")
parser.add_argument('-i', '--input', action='store', dest="pcap_in", default=None,
                    required=True, help="Input Pcap File.")
parser.add_argument('-d', '--outdir', action='store', dest="dir_out", default=None,
                    required=True, help="Output Pcap Directory.")
parser.add_argument('-o', '--output', action='store', dest="pcap_out", default=None,
                    required=True, help="Output Pcap File.")
parser.add_argument('-c', '--count', action='store', dest="max_count", default=1, type=int,
                    required=False, help="Read Packet Count / NanoSecond Count.")
args = parser.parse_args()

split_type = args.split_type
pcap_input = args.pcap_in
dir_output = args.dir_out
pcap_output = args.pcap_out
read_count = args.max_count
pause_count = read_count

folder = os.path.exists(dir_output)
if not folder:
    os.makedirs(dir_output)

# read pcap
print("Begin to process %s" % pcap_input)

out_packets = []
time_begin = 0
count = 0
last_count = 0
of_index = 0
for pkt in PcapReader(pcap_input):
    count += 1
    #pkt_time = pkt[1].sec * 10**9 + pkt[1].usec
    pkt_time = int(round(pkt.time * 10**9))
    if time_begin == 0:
        time_begin = pkt_time
        print("Begin Time %d" % time_begin)
    if split_type == 0:
        pkt_nanotime= pkt_time
        time_pass = pkt_nanotime - time_begin
        if time_pass >= read_count:
            print("[W] " + pcap_output+"_"+str(of_index)+".pcap total %d packets." % (count-last_count) )
            last_count = count
            wrpcap(dir_output+"/"+pcap_output+"_"+str(of_index)+".pcap", out_packets, append=False)
            read_count = read_count + pause_count
            del out_packets[:]
            of_index+=1
        out_packets.append(pkt)
    elif split_type == 1:
        if count <= read_count:
            out_packets.append(pkt)
        else:
            print("[W] " + pcap_output+"_"+str(of_index)+".pcap total %d packets." % (count-last_count) )
            last_count = count
            wrpcap(dir_output+"/"+pcap_output+"_"+str(of_index)+".pcap", out_packets, append=False)
            read_count = read_count + pause_count
            del out_packets[:]
            of_index+=1
    if count % 1000000 == 0:
        print("Processed %d packets, current time %d, time passed %d..." % (count,pkt_time, pkt_time - time_begin))
