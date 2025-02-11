
#!/usr/bin/env python3

from scapy.all import Packet, bind_layers, BitField, ShortField, IntField, Ether, IP, UDP, sendp, get_if_hwaddr, sniff, PacketListField
import pandas as pd
import sys
from time import time, perf_counter_ns


class InBandNetworkTelemetry(Packet):
    fields_desc = [
        BitField("switchID_t", 0, 31),
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


class NodeCount(Packet):
    name = "nodeCount"
    fields_desc = [ShortField("id", 0),
                   ShortField("count", 0),
                   PacketListField("INT", [], InBandNetworkTelemetry, count_from=lambda pkt: (pkt.count * 1))]


class INTP4Pi:
    def __init__(self):
        self.id = 0
        self.downlink_enq_qdepth = 0
        self.downlink_deq_qdepth = 0
        self.downlink_deq_timedelta = 0
        self.downlink_processing_time = 0
        self.uplink_enq_qdepth = 0
        self.uplink_deq_qdepth = 0
        self.uplink_deq_timedelta = 0
        self.uplink_processing_time = 0


def handle_pkt(pkt, queues):
    if IP in pkt and pkt[IP].proto == 253 and pkt[NodeCount].count > 0:
        dataINT = INTP4Pi()
        int_id = pkt[NodeCount].id
        timestamp = perf_counter_ns()
        int_header = pkt[NodeCount].INT[-1]
        qid = int_header[InBandNetworkTelemetry].qid
        for int_pkt in pkt[NodeCount].INT:
            telemetry = int_pkt[InBandNetworkTelemetry]
            #print("INT ID: ", int_id)
            if telemetry.switchID_t == 1:
                #print(f"Queue {qid} - Downlink/WiFi")
                dataINT.downlink_enq_qdepth = telemetry.enq_qdepth
                dataINT.downlink_deq_qdepth = telemetry.deq_qdepth
                dataINT.downlink_deq_timedelta = telemetry.deq_timedelta
                dataINT.downlink_processing_time = telemetry.processing_time
            else:
                #print(f"Queue {qid} - Uplink/Wired")
                dataINT.uplink_enq_qdepth = telemetry.enq_qdepth
                dataINT.uplink_deq_qdepth = telemetry.deq_qdepth
                dataINT.uplink_deq_timedelta = telemetry.deq_timedelta
                dataINT.uplink_processing_time = telemetry.processing_time

            '''print("Enqueue Timestamp:", telemetry.enq_timestamp)
            print("Enqueue Queue Depth:", telemetry.enq_qdepth)
            print("Dequeue Timedelta:", telemetry.deq_timedelta)
            print("Dequeue Queue Depth:", telemetry.deq_qdepth)
            if telemetry.switchID_t == 1:
                print("------------------------------")
            else:
                print("\n")'''
            
        print("QID: ", qid)
        print("INT ID: ", int_id)
        print("Timestamp: ", timestamp)
        print("Donwlink Processing Time: ", dataINT.downlink_processing_time)
        print("Donwlink Queue Time: ", dataINT.downlink_deq_timedelta)
        print("Upink Processing Time: ", dataINT.uplink_processing_time)
        print("Uplink Queue Time: ", dataINT.uplink_deq_timedelta)
        print()

        
        int_df = pd.DataFrame([{'id': int_id,
                                'timestamp': timestamp,
                                'downlink deq_timedelta': dataINT.downlink_deq_timedelta,
                                'downlink processing_time': dataINT.downlink_processing_time,
                                'uplink deq_timedelta': dataINT.uplink_deq_timedelta,
                                'uplink processing_time': dataINT.uplink_processing_time,
                                'downlink enq_qdepth': dataINT.downlink_enq_qdepth,
                                'downlink deq_qdepth': dataINT.downlink_deq_qdepth,
                                'uplink enq_qdepth': dataINT.uplink_enq_qdepth,
                                'uplink deq_qdepth': dataINT.uplink_deq_qdepth
                               }])
                   
        queues[qid] = pd.concat([queues[qid], int_df], ignore_index=True)
        



def main():
    if len(sys.argv) == 3:
        int_columns = [ 'id',
                        'timestamp',
                        'downlink deq_timedelta',
                        'downlink processing_time',
                        'uplink deq_timedelta',
                        'uplink processing_time',
                        'downlink enq_qdepth', 
                        'downlink deq_qdepth', 
                        'uplink enq_qdepth', 
                        'uplink deq_qdepth' 
                      ]
        queues = []
        numq = 3 # number of queues, change when add more queues
        while numq > 0:
            queues.append(pd.DataFrame(columns=int_columns))
            numq = numq - 1
        
        iface = 'wlxc04a001d90b7' #'wlp6s0'
        bind_layers(IP, NodeCount, proto=253)
        bind_layers(Ether, IP)
        timeEx = int(sys.argv[2])

        print("Waiting packets...")
        sniff(iface=iface, prn=lambda x: handle_pkt(x, queues), timeout=timeEx)

        print("Saving collect INT data...")
        experiment = sys.argv[1]
        #path = f'../scenarios/{experiment}'
        path = 'data'
        nq_saved = 0
        for qid, queue in enumerate(queues):
            if len(queue.index) > 0:
                filename = f'receiver_queue{qid}.csv'
                queue.to_csv(f'{path}/{filename}')
                nq_saved = nq_saved + 1
        print(f"Successfully saved {nq_saved} queues")
    else:
        print("2 arguments are expected: ID and duration (in seconds) of the experiment...")    


if __name__ == '__main__':
    main()
