#! /usr/bin/python
# -*- coding:utf8 -*-
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

if __name__ == "__main__":
    pcap_statistics = loadJsonToDict( IN_PCAP_ANA_JSON )
    for ip_pair in pcap_statistics['ip_pair_pkt_cnt_table']:
        ip_src = ip_pair[1]
        ip_dst = ip_pair[0]
