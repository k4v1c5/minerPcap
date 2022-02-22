#! /usr/bin/env python
import sys
import logging

logger = logging.getLogger("scapy")
logger.setLevel(logging.INFO)

import scapy.all as scapy


def listprint(attributum):
    for list_row in attributum:
        print(list_row)


def sniff_packets(iface=None, source=None):
    """
    Sniff 80 port packets with `iface`, if None (default), then the
    Scapy's default interface is used
    """
    if iface:
        # port 80 for http (generally)
        # `process_packet` is the callback
        scapy.sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
    else:
        # sniff with default interface
        cv = scapy.rdpcap(source)
        for pktx in cv:
            pktx.sniff(filter="port 80", prn=process_packet, store=False)


def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    if packet.haslayer(scapy.HTTPRequest):
        # if this packet is an HTTP Request
        # get the requested URL
        url = packet[scapy.HTTPRequest].Host.decode() + packet[scapy.HTTPRequest].Path.decode()
        # get the requester's IP Address
        ip = packet[scapy.IP].src
        # get the request method
        method = packet[scapy.HTTPRequest].Method.decode()
        print(f"\n[+] {ip} Requested {url} with {method}")
        if show_raw and packet.haslayer(scapy.Raw) and method == "POST":
            # if show_raw flag is enabled, has raw data, and the requested method is "POST"
            # then show raw
            print(f"\n[*] Some useful Raw data: {packet[scapy.Raw].load}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, this is useful when you're a man in the middle." \
                                                 + "It is suggested that you run arp spoof before you use this script, otherwise it'll sniff your personal packets")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("-f", "--file", help="PCAP file")
    parser.add_argument("--show-raw", dest="show_raw", action="store_true",
                        help="Whether to print POST raw data, such as passwords, search queries, etc.")
    # parse arguments
    args = parser.parse_args()
    print(repr(args))
    if args.iface is not None:
        source = args.iface
    elif args.file is not None:
        source = args.file

    show_raw = args.show_raw
    sniff_packets(args.iface, source)

    # pcap = sys.argv[1]
    srcs = []
    dsts = []
    headers = []

    a = scapy.rdpcap(source)
    # pkt = a[0]
    for pkt in a:
        srcs.append(pkt.payload.fields.get('src'))
        dsts.append(pkt.payload.fields.get('dst'))
        headers.append(a.stats)
        srcs1 = list(set(srcs))
        dsts1 = list(set(dsts))
        unionList = list(set(srcs1) | set(dsts1))

    # print(repr(src))
    # print(repr(dst))
    print("Forrás IP címek:")
    listprint(srcs1)

    print("Cél IP címek:")
    listprint(dsts1)

    print("Union list:")
    listprint(unionList)

# srcs = []
# dsts = []
# pcap = sys.argv[1]
# extraction = pcapkit.extract(fin=pcap, nofile=True, tcp=True, strict=True)
# frames = extraction.frame
#
# for row in frames:
#     flag = pcapkit.IP in row
#     udp = pcapkit.protocols.transport.udp in row
#     print(udp)
#     srcs.append(str(row[pcapkit.IP].src) if flag else "None")
#     dsts.append(row[pcapkit.IP].dst if flag else "None")
#
#
# print("Forrás IP címek:")
# listprint(srcs1)
#
# print("Cél IP címek:")
# listprint(dsts1)
#
# print("Union list:")
# listprint(unionList)
#
# for packet in extraction.reassembly.tcp:
#     for reassembly in packet.packets:
#         if pcapkit.HTTP in reassembly.protochain:
#             print(reassembly.info)
