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
├── cm_sketch.py                   # count-min sketch reader.
├── common.py                      # params
├── common.pyc
├── es_sketch.py                   # elastic sketch reader.
├── input
├── output
├── pcap_split_v2.py               # split pcap file by time or count.
├── pkts -> /home/hzheng/pkts/
└── README.md                   
## Usage


## Use Case

```txt

chmod +x  analyze_pcap.py
./analyze_pcap.py

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
17.252.185.205  => 150.192.205.16   Packet Count = 40   Flow Size (Bytes) = 2640      
103.137.195.60  => 133.164.161.130  Packet Count = 38   Flow Size (Bytes) = 56024     
........
============================================================================================
5-tuple flow count table:
[150.192.58.186 :873   => 113.53.170.196 :60051 | 6 ] Packet Count= 90  Flow Size (Bytes)= 147844    
[150.192.58.186 :80    => 27.118.192.58  :54948 | 6 ] Packet Count= 51  Flow Size (Bytes)= 84514     
[150.192.205.16 :52213 => 17.252.185.205 :80    | 6 ] Packet Count= 40  Flow Size (Bytes)= 2640      
[133.164.161.130:52364 => 103.137.195.60 :443   | 6 ] Packet Count= 38  Flow Size (Bytes)= 56024     
........   
============================================================================================

```

