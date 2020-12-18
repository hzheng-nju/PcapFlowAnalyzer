#! /usr/bin/python
# -*- coding:utf8 -*-
import scapy
import os
import json
from scapy.all import *
from scapy.utils import PcapReader
import argparse
import time

parser = argparse.ArgumentParser(description='Process pcap file and split into subfile. NOTE: Only output first sub pcap.')
parser.add_argument('-i', '--input', action='store', dest="pcap_in", default=None,
                    required=True, help="Input Pcap File.")
parser.add_argument('-d', '--outdir', action='store', dest="dir_out", default=None,
                    required=True, help="Output Pcap Directory.")
parser.add_argument('-o', '--output', action='store', dest="pcap_out", default=None,
                    required=True, help="Output Pcap File.")
parser.add_argument('-c', '--count', action='store', dest="max_count", default=0x1f1f1f1f,
                           type=int, required=False, help="Read Packet Count.")
args = parser.parse_args()

pcap_input = args.pcap_in
dir_output = args.dir_out
pcap_output = args.pcap_out
max_count = args.max_count

folder = os.path.exists(dir_output)
if not folder:
    os.makedirs(dir_output)
dir_output = dir_output + "/"

## TO statistic these data.
pcap_statistics = {
	'pkt_num' : 0,
	'ipv4_num' : 0,
	'ipv6_num' : 0,
	# Only for ipv4
	'tcp_num' : 0,
	'udp_num' : 0,
	'flow_set_ip_src' : {},     # (ipv4_dst, ipv4_src)
	'flow_num_ip_src' : 0,
	'flow_set_ip_dst' : {},     # (ipv4_dst, ipv4_src)
	'flow_num_ip_dst' : 0,
	'flow_set_ip_pair' : {},     # (ipv4_dst, ipv4_src)
	'flow_num_ip_pair' : 0,
	'flow_set_5_tuple' : {},     # (ipv4_dst, ipv4_src, dport, sport, protocol)
	'flow_num_5_tuple' : 0,
	'src_ip_pkt_cnt_table' : dict(),
	'src_ip_flow_size_table' : dict(),
	'dst_ip_pkt_cnt_table' : dict(),
	'dst_ip_flow_size_table' : dict(),
        'ip_pair_pkt_cnt_table' : dict(),    # <ip_pair : pkt_count>
	'5_tuple_pkt_cnt_table' : dict(),    # <5-tuple : pkt_count>
	'ip_pair_flow_size_table' : dict(),  # <ip_pair : flow_size>
	'5_tuple_flow_size_table' : dict()   # <5-tuple : flow_size>
}

# read pcap
print("Begin to process %s" % pcap_input)
pause = 0
for packet in PcapReader(pcap_input):
    pause += 1
    if pause >= max_count:
        break
    pcap_statistics['pkt_num'] += 1
    if packet.haslayer("IPv6"):
    	pcap_statistics['ipv6_num'] += 1
    if packet.haslayer("IP"):
    	pcap_statistics['ipv4_num'] += 1
    	ipv4_src = packet['IP'].src
    	ipv4_dst = packet['IP'].dst
    	sport = 0
    	dport = 0
    	protocol = 0
    	if packet.haslayer("TCP"):
    		protocol = 6
    		sport = packet['TCP'].sport
    		dport = packet['TCP'].dport
    		pcap_statistics["tcp_num"] += 1
    	if packet.haslayer("UDP"):
    		protocol = 17
    		sport = packet['UDP'].sport
    		dport = packet['UDP'].dport
    		pcap_statistics["udp_num"] += 1
        ip_dst_key  = (ipv4_dst)
        ip_src_key  = (ipv4_src)
    	ip_pair_key = (ipv4_dst, ipv4_src)
    	five_tuple_key = (ipv4_dst, ipv4_src, dport, sport, protocol)
    	pkt_len = len(packet) + 4   ## len(pkt) can get full packet length without crc(4 Bytes)
    	if ip_dst_key not in pcap_statistics['flow_set_ip_dst']:
    		# If not exist, add to set
    		pcap_statistics['flow_set_ip_dst'][ip_dst_key] = 1
    		pcap_statistics['flow_num_ip_dst'] += 1
    		pcap_statistics['dst_ip_pkt_cnt_table'][ip_dst_key] = 0
    		pcap_statistics['dst_ip_flow_size_table'][ip_dst_key] = 0
    	pcap_statistics['dst_ip_pkt_cnt_table'][ip_dst_key] += 1
    	pcap_statistics['dst_ip_flow_size_table'][ip_dst_key] += pkt_len

    	if ip_src_key not in pcap_statistics['flow_set_ip_src']:
    		# If not exist, add to set
    		pcap_statistics['flow_set_ip_src'][ip_src_key] = 1
    		pcap_statistics['flow_num_ip_src'] += 1
    		pcap_statistics['src_ip_pkt_cnt_table'][ip_src_key] = 0
    		pcap_statistics['src_ip_flow_size_table'][ip_src_key] = 0
    	pcap_statistics['src_ip_pkt_cnt_table'][ip_src_key] += 1
    	pcap_statistics['src_ip_flow_size_table'][ip_src_key] += pkt_len

    	if ip_pair_key not in pcap_statistics['flow_set_ip_pair']:
    		# If not exist, add to set
    		pcap_statistics['flow_set_ip_pair'][ip_pair_key] = 1
    		pcap_statistics['flow_num_ip_pair'] += 1
    		pcap_statistics['ip_pair_pkt_cnt_table'][ip_pair_key] = 0
    		pcap_statistics['ip_pair_flow_size_table'][ip_pair_key] = 0
    	pcap_statistics['ip_pair_pkt_cnt_table'][ip_pair_key] += 1
    	pcap_statistics['ip_pair_flow_size_table'][ip_pair_key] += pkt_len

    	if five_tuple_key not in pcap_statistics["flow_set_5_tuple"]:
    		pcap_statistics['flow_set_5_tuple'][five_tuple_key] = 1
    		pcap_statistics['flow_num_5_tuple'] += 1
    		pcap_statistics['5_tuple_pkt_cnt_table'][five_tuple_key] = 0
    		pcap_statistics['5_tuple_flow_size_table'][five_tuple_key] = 0
    	pcap_statistics['5_tuple_pkt_cnt_table'][five_tuple_key] += 1
    	pcap_statistics['5_tuple_flow_size_table'][five_tuple_key] += pkt_len

## Conclude the Result.
print("pkt_num : %d" % pcap_statistics["pkt_num"])
print("ipv4_num : %d" % pcap_statistics["ipv4_num"])
print("ipv6_num : %d" % pcap_statistics["ipv6_num"])
print("tcp_num(ipv4) : %d" % pcap_statistics["tcp_num"])
print("udp_num(ipv4) : %d" % pcap_statistics["udp_num"])
print("flow_num_ip_src(ipv4)   : %d" % pcap_statistics["flow_num_ip_src"])
print("flow_num_ip_dst(ipv4)   : %d" % pcap_statistics["flow_num_ip_dst"])
print("flow_num_ip_pair(ipv4)  : %d" % pcap_statistics["flow_num_ip_pair"])
print("flow_num_5_tuple(ipv4)  : %d" % pcap_statistics["flow_num_5_tuple"])
print("For detail please see result.txt.")

#### Write txt Result.
of = open(dir_output + pcap_output + ".txt", "w")
of.write("==============================================================================================================\n")
of.write("Overview:\n")
of.write("==============================================================================================================\n")
of.write("pkt_num : %d \n" % pcap_statistics["pkt_num"])
of.write("ipv4_num : %d \n" % pcap_statistics["ipv4_num"])
of.write("ipv6_num : %d \n" % pcap_statistics["ipv6_num"])
of.write("tcp_num(ipv4) : %d \n" % pcap_statistics["tcp_num"])
of.write("udp_num(ipv4) : %d \n" % pcap_statistics["udp_num"])
of.write("flow_num_ip_src(ipv4)  : %d \n" % pcap_statistics["flow_num_ip_src"])
of.write("flow_num_ip_dst(ipv4)  : %d \n" % pcap_statistics["flow_num_ip_dst"])
of.write("flow_num_ip_pair(ipv4)  : %d \n" % pcap_statistics["flow_num_ip_pair"])
of.write("flow_num_5_tuple(ipv4)  : %d \n" % pcap_statistics["flow_num_5_tuple"])
of.write("==============================================================================================================\n")
of.write("IP Pair flow count table:\n")
## Sorted ==> Get a list.
ip_pair_sorted_pkt_cnt = sorted(pcap_statistics["ip_pair_pkt_cnt_table"].items(), key=lambda item:item[1],reverse=True)
tplt1 = "{0:<16} => {1:<16}\t Packet Count = {2:<10}\t Flow Size (Bytes) = {3:<10}\n"
for ip_pair in ip_pair_sorted_pkt_cnt:
	pkt_cnt = pcap_statistics["ip_pair_pkt_cnt_table"][ip_pair[0]]  ## Ip_pair is a list.
	flow_size = pcap_statistics["ip_pair_flow_size_table"][ip_pair[0]]
	# of.write("- %s => %s  : pkt_count=%d, flow_size=%d  (Bytes). \n" % (ip_pair[0][0], ip_pair[0][1], pkt_cnt, flow_size))
	of.write( tplt1.format(ip_pair[0][1], ip_pair[0][0], pkt_cnt, flow_size))
of.write("==============================================================================================================\n")
of.write("5-tuple flow count table:\n")
five_tuple_sorted_pkt_cnt = sorted(pcap_statistics["5_tuple_pkt_cnt_table"].items(), key=lambda item:item[1],reverse=True)
tplt2 = "[{0:<16}:{2:<5} => {1:<16}:{3:<5} | {4:<4}]\t Packet Count = {5:<10}\t Flow Size (Bytes) = {6:<10}\n"
for five_tuple in five_tuple_sorted_pkt_cnt:
	pkt_cnt = pcap_statistics['5_tuple_pkt_cnt_table'][five_tuple[0]]
	flow_size = pcap_statistics["5_tuple_flow_size_table"][five_tuple[0]]
	of.write(tplt2.format(five_tuple[0][1], five_tuple[0][0], five_tuple[0][3], five_tuple[0][2], five_tuple[0][4], pkt_cnt, flow_size))
of.write("==============================================================================================================\n")
of.close()


### Write json Result
def stringify_keys(d):
    """Convert a dict's keys to strings if they are not."""
    for key in d.keys():

        # check inner dict
        if isinstance(d[key], dict):
            value = stringify_keys(d[key])
        else:
            value = d[key]

        # convert nonstring to string if needed
        if not isinstance(key, str):
            try:
                d[str(key)] = value
            except Exception:
                try:
                    d[repr(key)] = value
                except Exception:
                    raise

            # delete old key
            del d[key]
    return d
jsObj = json.dumps(stringify_keys(pcap_statistics))
fileObject = open(dir_output + pcap_output + ".json", 'w')
fileObject.write(jsObj)
fileObject.close()
