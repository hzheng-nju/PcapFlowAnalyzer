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

class cm_sketch:
    def __init__(self):
        pass

    def load(self, np_file):
        self._sketch = np.load( np_file )

    def access(self, ipv4_dst, ipv4_src):
        index_d1 = hash_index(ipv4_dst, ipv4_src, CM_SKETCH_HASH_SD1, CM_SKETCH_COL)
        index_d2 = hash_index(ipv4_dst, ipv4_src, CM_SKETCH_HASH_SD2, CM_SKETCH_COL)
        index_d3 = hash_index(ipv4_dst, ipv4_src, CM_SKETCH_HASH_SD3, CM_SKETCH_COL)
        index_d4 = hash_index(ipv4_dst, ipv4_src, CM_SKETCH_HASH_SD4, CM_SKETCH_COL)
        index_d5 = hash_index(ipv4_dst, ipv4_src, CM_SKETCH_HASH_SD5, CM_SKETCH_COL)
        cnt_d1 = self._sketch[0][index_d1]
        cnt_d2 = self._sketch[1][index_d2]
        cnt_d3 = self._sketch[2][index_d3]
        cnt_d4 = self._sketch[3][index_d4]
        cnt_d5 = self._sketch[4][index_d5]
        return min(cnt_d1, cnt_d2, cnt_d3, cnt_d4, cnt_d5)

if __name__ == "__main__":
    pcap_statistics = loadJsonToDict( IN_PCAP_ANA_JSON )
    sketch = cm_sketch()
    sketch.load( CM_SKETCH_IN_NPY )

    of = open(CM_OUT_SKETCH_ANA_TXT, "w")
    ## For plot
    plt_x = range(len(pcap_statistics['ip_pair_pkt_cnt_table']))
    plt_y_real = [0] * len(plt_x)
    plt_y_sketch = [0] * len(plt_x)
    index = 0
    max_cnt = 0
    total_cnt = 0
    average_relative_error = 0
    temp_relative_error_sum = 0
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
        relative_error = (abs(estimate - real_cnt)/ real_cnt) * 100
        temp_relative_error_sum += relative_error
        of.write("{0:<16} => {1:<16}\t real_cnt={2:<5}\t estimate = {3:<5} \t relative_error={4:<5}\n".format \
        				  (ip_src, ip_dst, real_cnt, estimate, relative_error))
    of.write("Average Relative Error = %d / %d = %d \n" % (temp_relative_error_sum, index, temp_relative_error_sum / index))
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
    plt.savefig(CM_OUT_SKETCH_ANA_PNG, dpi=600)
