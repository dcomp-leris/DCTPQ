#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct

from time import sleep
from scapy.all import Packet, bind_layers, XByteField, FieldLenField, BitField, ShortField, IntField, PacketListField, \
    Ether, IP, UDP, sendp, get_if_hwaddr, sniff


class InBandNetworkTelemetry(Packet):
    fields_desc = [BitField("switchID_t", 0, 31),
                   BitField("ingress_port", 0, 9),
                   BitField("egress_port", 0, 9),
                   BitField("egress_spec", 0, 9),
                   BitField("priority", 0, 3),
                   BitField("qid", 0, 5),
                   BitField("ingress_global_timestamp", 0, 48),
                   BitField("egress_global_timestamp", 0, 48),
                   BitField("enq_timestamp", 0, 32),
                   BitField("enq_qdepth", 0, 19),
                   BitField("deq_timedelta", 0, 32),
                   BitField("deq_qdepth", 0, 19),
                   BitField("processing_time", 0, 32)
                   ]
    """any thing after this packet is extracted is padding"""

    def extract_padding(self, p):
        return "", p


class nodeCount(Packet):
    name = "nodeCount"
    fields_desc = [ShortField("id", 0),
                   ShortField("count", 0),
                   PacketListField("INT", [], InBandNetworkTelemetry, count_from=lambda pkt: (pkt.count * 1))]


def handle_pkt(pkt):
    if IP in pkt and (pkt[IP].proto == 253 or pkt[IP].proto == 254 or pkt[IP].proto == 255):
        if pkt[nodeCount].count > 0:
            pkt.show2()


def main():
    iface = 'wlp6s0' 
    bind_layers(IP, nodeCount, proto=253)
    bind_layers(IP, nodeCount, proto=254)
    bind_layers(IP, nodeCount, proto=255)
    print('Esperando pacotes...')
    sniff(iface=iface, prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()