import sys
import pcapkit

pcap = sys.argv[1]
extraction = pcapkit.extract(fin=pcap, nofile=True)
frame0 = extraction.frame[0]
flag = pcapkit.IP in frame0
tcp = frame0[pcapkit.IP] if flag else None
