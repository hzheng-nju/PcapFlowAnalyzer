#! /usr/bin/python
import scapy
import os
import json
from scapy.all import *
from scapy.utils import PcapReader
from common import *

def analyzePcap(pcap, pcap_statistics):
	packets = rdpcap(pcap)
	# packets[1].pdfdump(layer_shift=1)
	# packets[1].psdump("/tmp/isakmp_pkt.eps",layer_shift=1)
	for packet in packets:
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
			ip_pair_key = (ipv4_dst, ipv4_src)
			five_tuple_key = (ipv4_dst, ipv4_src, dport, sport, protocol)
			pkt_len = len(packet) + 4   ## len(pkt) can get full packet length without crc(4 Bytes)
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
			# print(" %s => %s " % (ipv4_src, ipv4_dst))

def resultWriter(pcap_statistics, outfile):
	of = open(outfile, "w")
	of.write("==============================================================================================================\n")
	of.write("Overview:\n")
	of.write("==============================================================================================================\n")
	of.write("pkt_num : %d \n" % pcap_statistics["pkt_num"])
	of.write("ipv4_num : %d \n" % pcap_statistics["ipv4_num"])
	of.write("ipv6_num : %d \n" % pcap_statistics["ipv6_num"])
	of.write("tcp_num(ipv4) : %d \n" % pcap_statistics["tcp_num"])
	of.write("udp_num(ipv4) : %d \n" % pcap_statistics["udp_num"])
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
		of.write( tplt1.format(ip_pair[0][0], ip_pair[0][1], pkt_cnt, flow_size))
	of.write("==============================================================================================================\n")
	of.write("5-tuple flow count table:\n")
	five_tuple_sorted_pkt_cnt = sorted(pcap_statistics["5_tuple_pkt_cnt_table"].items(), key=lambda item:item[1],reverse=True)
	tplt2 = "[{0:<16}:{2:<5} => {1:<16}:{3:<5} | {4:<4}]\t Packet Count = {5:<10}\t Flow Size (Bytes) = {6:<10}\n"
	for five_tuple in five_tuple_sorted_pkt_cnt:
		pkt_cnt = pcap_statistics['5_tuple_pkt_cnt_table'][five_tuple[0]]
		flow_size = pcap_statistics["5_tuple_flow_size_table"][five_tuple[0]]
		of.write(tplt2.format(five_tuple[0][1], five_tuple[0][0], five_tuple[0][3], five_tuple[0][2], five_tuple[0][4], pkt_cnt, flow_size))
	of.write("==============================================================================================================\n")

pcap_statistics = {
	'pkt_num' : 0,
	'ipv4_num' : 0,
	'ipv6_num' : 0,
	# Only for ipv4
	'tcp_num' : 0,
	'udp_num' : 0,
	'flow_set_ip_pair' : {},     # (ipv4_dst, ipv4_src)
	'flow_num_ip_pair' : 0,
	'flow_set_5_tuple' : {},     # (ipv4_dst, ipv4_src, dport, sport, protocol)
	'flow_num_5_tuple' : 0,
        'ip_pair_pkt_cnt_table' : dict(),    # <ip_pair : pkt_count>
	'5_tuple_pkt_cnt_table' : dict(),    # <5-tuple : pkt_count>
	'ip_pair_flow_size_table' : dict(),  # <ip_pair : flow_size>
	'5_tuple_flow_size_table' : dict()   # <5-tuple : flow_size>
}

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

if __name__ == "__main__":
    analyzePcap( IN_PCAP_FILE, pcap_statistics)
    print("pkt_num : %d" % pcap_statistics["pkt_num"])
    print("ipv4_num : %d" % pcap_statistics["ipv4_num"])
    print("ipv6_num : %d" % pcap_statistics["ipv6_num"])
    print("tcp_num(ipv4) : %d" % pcap_statistics["tcp_num"])
    print("udp_num(ipv4) : %d" % pcap_statistics["udp_num"])
    print("flow_num_ip_pair(ipv4)  : %d" % pcap_statistics["flow_num_ip_pair"])
    print("flow_num_5_tuple(ipv4)  : %d" % pcap_statistics["flow_num_5_tuple"])
    print("For detail please see result.txt.")
    resultWriter(pcap_statistics, OUT_PCAP_ANA_TXT)
    jsObj = json.dumps(stringify_keys(pcap_statistics))
    fileObject = open(OUT_PCAP_ANA_JSON, 'w')
    fileObject.write(jsObj)
    fileObject.close()
