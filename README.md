# A simple pcap file parser

This is a simple script to parse a pacp file into the flow view of ip-pair and 5-tuple.

## Requirements

* Python 2.7.12
* Scapy 2.4.4
* matplotlib
* numpy

``` bash
pip install scapy
sudo apt install texlive-latex-base   ## For packet pdfdump function.
```

## Introduce

```bash
<ROOT>
├── analyze_pcap.py                # analyze the pcap file, save as json and readable txt file. 
├── pcap_split_v2.py               # split pcap file by time or count.
├── pcap2dat.py                    # read pcap and save as dat file. Read code's comments to see how to use it.
├── data                           # test data directory.
├── README.md 
└── test100                        # test cmd output dir.
```

## Use Case

### Analyze a pcap file

analyze_pcap.py can analyze pcap file, output txt file to read and json file to reuse.

* The txt format file is used for human to understand the flow distribution of the pcap file.
* The json format file is used for other program to do some specific tasks.


```bash
### Add executable permissions
chmod +x  *.py
./analyze_pcap.py -i data/mini-100-ok.pcap -d test100 -o test100
```
This is example output of txt file.

```txt
Begin to process data/mini-100-ok.pcap
pkt_num : 100
ipv4_num : 96
ipv6_num : 4
tcp_num(ipv4) : 90
udp_num(ipv4) : 0
flow_num_ip_src(ipv4)   : 15
flow_num_ip_dst(ipv4)   : 18
flow_num_ip_pair(ipv4)  : 18
flow_num_5_tuple(ipv4)  : 18
For detail please see result.txt.

### Example txt file result.
============================================================================================
Overview:
============================================================================================
pkt_num : 1000 
ipv4_num : 915 
ipv6_num : 85 
tcp_num(ipv4) : 877 
udp_num(ipv4) : 22 
flow_num_ip_pair(ipv4)  : 86 
flow_num_5_tuple(ipv4)  : 92 
============================================================================================
IP Pair flow count table:
113.53.170.196  => 150.192.58.186   Packet Count = 90   Flow Size (Bytes) = 147844    
27.118.192.58   => 150.192.58.186   Packet Count = 51   Flow Size (Bytes) = 84514       
........
============================================================================================
5-tuple flow count table:
[150.192.58.186 :873   => 113.53.170.196 :60051 | 6 ] Packet Count= 90  Flow Size (Bytes)= 147844    
[150.192.58.186 :80    => 27.118.192.58  :54948 | 6 ] Packet Count= 51  Flow Size (Bytes)= 84514        
........   
============================================================================================
```

* The json file is organized as the following format. The example of how to use the json file is shown in [read_pcap_json.py](./read_pcap_json.py).

```python
### Example json file format
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
```


### Split a pcap file

The pcap_split_v2.py can split a pcap file by count or time (In nanosecond).

```bash
## Split every 10 packets, in this example, the meaning of -c is packetnum.
./pcap_split_v2.py -i data/mini-100-ok.pcap -t 1 -c 10 -d test100 -o test
Begin to process data/mini-100-ok.pcap
Begin Time 1585112400240760064
[W] test_0.pcap total 11 packets.
[W] test_1.pcap total 10 packets.
[W] test_2.pcap total 10 packets.
[W] test_3.pcap total 10 packets.
[W] test_4.pcap total 10 packets.
[W] test_5.pcap total 10 packets.
[W] test_6.pcap total 10 packets.
[W] test_7.pcap total 10 packets.
[W] test_8.pcap total 10 packets.

## Split every 10 ms, in this example, the meaning of -c is nanosecond.
./pcap_split_v2.py -t 0 -i data/mini-100-ok.pcap -d test100_2 -o test -c 10000
Begin to process data/mini-100-ok.pcap
Begin Time 1585112400240760064
[W] test_0.pcap total 14 packets.
[W] test_1.pcap total 2 packets.
[W] test_2.pcap total 1 packets.
[W] test_3.pcap total 6 packets.
[W] test_4.pcap total 4 packets.
[W] test_5.pcap total 8 packets.
[W] test_6.pcap total 1 packets.
[W] test_7.pcap total 8 packets.
[W] test_8.pcap total 5 packets.
```

### Simpify a pcap file

This script convert pcap file into dat file, only store five tuple in it, (src_ip, sport, dst_ip, dport, protocol). total 13 Bytes per packet.

```bash
./pcap2dat.py -i data/mini-100-ok.pcap -o test100/mini.dat
```

How to read a dat file.

For python:

```python
#!/usr/bin/python
import socket
from common import *
import struct
import numpy as np
from mmhCDF import *

def bytes_to_int(bytes):
    result = 0
    for b in bytes:
        result = result * 256 + int(b,16)
    return result

f = open('five_sec_0.dat')
pkts = list()
readable_pkts = dict()
while True:
    try:
        pkt = f.read(13)
        ip_src = socket.inet_ntoa(pkt[0:4])
        sport  = struct.unpack("!H",pkt[4:6])[0]
        ip_dst = socket.inet_ntoa(pkt[6:10])
        dport  = struct.unpack("!H",pkt[10:12])[0]
        protocol = struct.unpack("b",pkt[12])[0]
    except:
        break
    print("%s:%d => %s:%d [%d]" % (ip_src, sport, ip_dst, dport, protocol))
```

For c++ :

```c++
TRACE trace;
void ReadInTraces(const char * datafileName)
{
    char datafileName[100];
    sprintf(datafileName, "%s%d.dat", trace_prefix, datafileCnt - 1);
    FILE *fin = fopen(datafileName, "rb");

    FIVE_TUPLE tmp_five_tuple;
    trace.clear();
    while(fread(&tmp_five_tuple, 1, 13, fin) == 13)
    {
        trace.push_back(tmp_five_tuple);
    }
    fclose(fin);
}
```



## End

For any questiones, feel free to create an issue.