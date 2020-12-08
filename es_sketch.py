#! /usr/bin/python
# -*- coding:utf8 -*-
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from common  import *
import zlib
import struct
import binascii
import json


class es_sketch:
    def __init__(self):
        pass

    def load(self, np_file):
        d = np.load(np_file, allow_pickle=True)
        data = dict(enumerate(d.flatten(), 1))[1]
        self._heavy1_all   = data['heavy1_voteAll']
        self._heavy1_table = data['heavy1_part']
        self._light_table  = data['light_part']

   
    def access(self, ipv4_dst, ipv4_src):
        heavy1_index = hash_index(ipv4_dst, ipv4_src, ES_SKETCH_HEAVY_HASH_SD1, ES_SKETCH_HEAVY_COL)
        light_index = hash_index(ipv4_dst, ipv4_src, ES_SKETCH_LIGHT_HASH_SD1, ES_SKETCH_LIGHT_COL)
        #(dst, src, vote, flag)
        heavyTuple = self._heavy1_table[heavy1_index]
        #print(heavyTuple)
        if( heavyTuple[0] == ipv4_dst and heavyTuple[1] == ipv4_src):
            if (heavyTuple[3] == 1): # have a light part.
                return heavyTuple[2] + self._light_table[light_index]
            else:
                return heavyTuple[2]
        else:
            return self._light_table[light_index]

    def show(self):
        print("Heavy1 Vote All : %d" % self._heavy1_all)
        print("Heavy1 Table : ")
        for item in self._heavy1_table:
            print(item)
        #print("Light Sketch: ")
        #print(self._light_table)
        pass

if __name__ == "__main__":
    pcap_statistics = loadJsonToDict( IN_PCAP_ANA_JSON )
    sketch = es_sketch()
    sketch.load( ES_SKETCH_IN_NPY )
    #sketch.show()

    of = open(ES_OUT_SKETCH_ANA_TXT, "w")
    ## For plot
    plt_x = range(len(pcap_statistics['ip_pair_pkt_cnt_table']))
    plt_y_real = [0] * len(plt_x)
    plt_y_sketch = [0] * len(plt_x)
    index = 0
    max_cnt = 0
    total_cnt = 0

    for ip_pair in pcap_statistics['ip_pair_pkt_cnt_table']:
        ip_src = ip_pair[1]
        ip_dst = ip_pair[0]
        estimate = sketch.access(ip_dst, ip_src)
        real_cnt = pcap_statistics['ip_pair_pkt_cnt_table'][ip_pair]
        total_cnt += real_cnt
        if estimate > max_cnt:
            max_cnt = estimate
        ### for plot
        plt_y_real[index] = real_cnt
        plt_y_sketch[index] = estimate
        index += 1
        if abs(estimate - real_cnt) <= real_cnt *  sketch_statistics['error_rate'] :
        	sketch_statistics['pass'] += 1
        	of.write("[PASS]  {0:<16} => {1:<16}\t real_cnt={2:<5}\t estimate = {3:<5} \n".format \
        	              (ip_src, ip_dst, real_cnt, estimate))
        else:
        	sketch_statistics['error'] += 1
        	of.write("[ERROR] {0:<16} => {1:<16}\t real_cnt={2:<5}\t estimate = {3:<5} \n".format \
        				  (ip_src, ip_dst, real_cnt, estimate))
    of.write("Total pass = %d \n" % sketch_statistics['pass'])
    of.write("Total error = %d \n" % sketch_statistics['error'])
    ## For plot
    points = zip(plt_y_real, plt_y_sketch)
    sorted_points = sorted(points)
    new_y1 = [point[0] for point in sorted_points]
    new_y2 = [point[1] for point in sorted_points]
    new_y3 = [point[0] + total_cnt * sketch_statistics['error_rate'] for point in sorted_points]
    ## 下面我没有渐变色
    plt.scatter( plt_x, new_y1, s=20, c='red', alpha=0.8, label='$Real\ Count$', marker='.')  ## alpha 透明图
    plt.scatter( plt_x, new_y2, s=20, c='blue', alpha=0.2, label='$Sketch\ Count$', marker='.')  ## size 是点的大小
    #plt.plot( plt_x, new_y3, s=20, c='green', alpha=1, label='$Upper\ Bound$', marker='_')  ## size 是点的大小
    plt.plot( plt_x, new_y3,  c='green',  label='$Error\ Bound$')  ## size 是点的大小
    plt.xlim(-100, len(plt_x)+1000)  # 坐标显示范围
    plt.xticks(())  # 坐标刻度
    plt.xlabel("Flows Ranked in Flow Size")
    
    #plt.ylim(0, max_cnt * 1.1)
    # plt.yticks((10,10000,1000000,10000000))  # ignore yticks
    plt.ylabel("Flow Size")
    plt.yscale('log')
    
    ## 这个是曲线图的图例
    #l1, = plt.plot()
    #l2, = plt.plot()
    #plt.legend(handles=[l1, l2], labels=['Real Count', 'Sketch Count'],  loc='best')
    
    plt.legend(loc='best')
    #plt.show()
    #plt.savefig('scatter.eps', dpi=600,format='eps')
    plt.savefig(ES_OUT_SKETCH_ANA_PNG, dpi=600)
