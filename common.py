######################################################################
# This file adjust params fro p4-sketch test.
# 2020/11/28
# Hao Zheng
######################################################################
import zlib
import struct
import binascii
import json


# For pcap analyze
#in_pcap_file= "./pkts/packets10M-paded.pcap"
#in_pcap_file= "./pkts/packets10M-paded-mtu-trunc.pcap"
#in_pcap_file= "./pkts/mini-10-ok.pcap"
IN_PCAP_FILE= "./pkts/fivesec0-paded-trunc.pcap"
OUT_PCAP_ANA_TXT= "./output/fiveSec0_statistic.txt"
OUT_PCAP_ANA_JSON = "./output/fiveSec0_statistic.json"

# For sketch analyze
#in_pacp_statistic_json = out_pacp_statistic_json
IN_PCAP_ANA_JSON = "./output/fiveSec0_statistic.json" #"./input/packets10M-paded-mtu-trunc-anaylize.json"

# For cm_sketch
CM_SKETCH_COL = 32768
CM_SKETCH_IN_NPY = "./input/cm_sketch_fiveSec0_d5w32768.npy" #"./input/sketch_result.npy"
CM_SKETCH_HASH_SD1= 0x18790314;
CM_SKETCH_HASH_SD2= 0x17770430;
CM_SKETCH_HASH_SD3= 0xabf278ac;
CM_SKETCH_HASH_SD4= 0x83291abc;
CM_SKETCH_HASH_SD5= 0x7382e401;
CM_OUT_SKETCH_ANA_TXT = "./output/cm_sketch_5sec0_d5w32768.txt"
CM_OUT_SKETCH_ANA_PNG = "./output/cm_sketch_5sec0_d5w32768.png"

# For elastic_sketch
ES_SKETCH_HEAVY_COL = 32768
ES_SKETCH_LIGHT_COL = 131072
ES_SKETCH_IN_NPY = "./input/es_sketch_fiveSec0_d5w32768.npy"
ES_SKETCH_HEAVY_HASH_SD1= 0x18790314;
ES_SKETCH_LIGHT_HASH_SD1= 0x17770430;
ES_OUT_SKETCH_ANA_TXT = "./output/es_sketch_5sec0_d5w32768.txt"
ES_OUT_SKETCH_ANA_PNG = "./output/es_sketch_5sec0_d5w32768.png"


def do_crc(s):
    n = zlib.crc32(s)
    return n + (1<<32) if n < 0 else n

def hash_index(ipv4_dst, ipv4_src, seed, col_num):
	hash1_func = zlib.crc32
	msg_val = b''
	arr1 = ipv4_dst.split(".")
	arr2 = ipv4_src.split(".")
	seed_bytes = struct.pack("!I", seed) 
	for i in range(len(arr1)):
		msg_val =  msg_val + struct.pack("B", int(arr1[i]))
	msg_val =  msg_val + seed_bytes
	for i in range(len(arr2)):
		msg_val =  msg_val + struct.pack("B", int(arr2[i]))
	# print(binascii.hexlify(msg_val))
	re = do_crc(msg_val) % col_num
	return  re


def s2d(d):
    #convert string key to tuple.
    for key in d.keys():
        try:
            d[eval(key)] = d[key]
            del d[key]
        except Exception:
            raise

def tuplize_keys(d):
    s2d(d['flow_set_ip_pair'])
    s2d(d['flow_set_5_tuple'])
    s2d(d['ip_pair_pkt_cnt_table'])
    s2d(d['5_tuple_pkt_cnt_table'])
    s2d(d['ip_pair_flow_size_table'])
    s2d(d['5_tuple_flow_size_table'])
    return d

def loadJsonToDict(js_file):
    js_dict = dict()
    with open(js_file) as js:
        js_dict = json.load(js)
    return tuplize_keys(js_dict)

#pcap_statistics = {
#	'pkt_num' : 0,
#	'ipv4_num' : 0,
#	'ipv6_num' : 0,
#	# Only for ipv4
#	'tcp_num' : 0,
#	'udp_num' : 0,
#	'flow_set_ip_pair' : {},     # (ipv4_dst, ipv4_src)      
#	'flow_num_ip_pair' : 0,
#	'flow_set_5_tuple' : {},     # (ipv4_dst, ipv4_src, dport, sport, protocol)
#	'flow_num_5_tuple' : 0,
#	'ip_pair_pkt_cnt_table' : dict(),
#	'5_tuple_pkt_cnt_table' : dict(),
#	'ip_pair_flow_size_table' : dict(),
#	'5_tuple_flow_size_table' : dict()
#}
sketch_statistics = {
	'error_rate' : 0.1,
	'pass' : 0,
	'error' : 0
}
