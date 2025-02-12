'''
Author: Alireza Shirmarz
Location: Leris Lab
Date: 20241230
'''

import cProfile
import logging
from scapy.all import sniff, sendp, UDP, Ether, IP
from scapy.layers.inet6 import IPv6
import threading
import time
from queue import Queue, Empty
from packet_classifier import PacketClassifier
import hashlib
import socket
import yaml
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
import crcmod
import ipaddress
from influxdb_client_3 import InfluxDBClient3, Point


''' General Variables '''
config_file = '/home/pi/DCTPQ/P4Pi/config.yaml'
# Model path configuration
model_path = 'dt_model.joblib'


# Network configuration
SRC_INTERFACE = 'eth1'  # Interface listen to TG


# Store the flows to avoid sending of the consecutive packets of the flows
#lookup_table = {} # lookup table to cache the  packets of the flow



# Initialize counters
packets_received = 0
packets_forwarded = 0



start_time = time.time()
#q_cache = Queue()


# Assuming classifier and container_table are defined elsewhere
global last_reset_time
last_reset_time = time.time()
#lookup_table = {}

# Initialize the dictionary
my_dict = {}

counter_CG_class = 0
CG_class_IPs = []
CG_first_octet = 13

def connectDB():
    token = "QIrU2j0_lzhvmPXJehNbnd9JIjA3c-DWu-smeAwdEWk0XGJIfjGTovzeJIH40mjtf5mxAV39AOfv45at9j-m8w==" #ADD TOKEN
    org = "Research"
    host = "https://us-east-1-1.aws.cloud2.influxdata.com"

    client = InfluxDBClient3(host=host, token=token, org=org)
    #client = 1
    return client


client = connectDB()
database = "CG-Monitoramento"
id = "test"


# Function to add or update an entry in the dictionary
def add_or_update_entry(key, value, allow_update=True):
    if key in my_dict.keys():
        if allow_update:
            #print(f"Key '{key}' exists. Updating the value.")
            my_dict[key] = value  # Update the existing entry
            return True
        else:
            #print(f"Key '{key}' exists. Update not allowed.")
            return False
    else:

        my_dict[key] = value
        return True
        '''
        if allow_update:
            #print(f"Key '{key}' does not exist. Adding new entry.")
            my_dict[key] = value  # Insert a new entry
            return True
        else:
            #print(f"Key '{key}' does not exist. Blocking action.")
            return False'''

# Convert IP address to bits
def ip_to_bits(ip):
    try:
        # Try to parse the IP address using ipaddress module
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError("Invalid IP address format")

    # Check if the IP address is IPv4
    if ip_obj.version == 4:
        return ''.join(format(int(octet), '08b') for octet in ip.split('.'))
    # Check if the IP address is IPv6
    elif ip_obj.version == 6:
        return ''.join(format(int(octet, 16), '016b') for octet in ip_obj.exploded.split(':'))



'''def ip_to_bits(ip):
    return ''.join(format(int(octet), '08b') for octet in ip.split('.'))'''

# Convert integer to bits
def port_to_bits(integer, bit_length=16):
    return format(integer, f'0{bit_length}b')

# Convert bits to CRC16
def bits_to_crc16(bits):
    crc16_func = crcmod.predefined.mkPredefinedCrcFun('crc-16')

    # Convert bit string to bytes
    byte_array = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

    crc = crc16_func(byte_array)
    return crc





''' Functions Definition '''
def load_config(yaml_file):
    with open(yaml_file, 'r') as file:
        config = yaml.safe_load(file)
    return config


# Set the reset time for lookup table

reset_time  = 8000      # it is set with config file
entry_num = 10          # it is set with config file

def reset_lookup_table_if_needed():
    global my_dict, last_reset_time
    current_time = time.time()
    if (current_time - last_reset_time) * 1000 >= reset_time  or len(my_dict) >= entry_num:  # Check if 100ms have passed
        my_dict = {}  # Reset the table
        last_reset_time = current_time
        classifier = PacketClassifier(model_path)






def forward_packet(packet):

    global packets_forwarded, bytes_forwarded, lookup_table, q_cache, i , packets_received, classifier, counter_CG_class, CG_first_octet, CG_class_IPs, client, database, id

    reset_lookup_table_if_needed()  # Check if it's time to reset the lookup_table
    controller = SimpleSwitchThriftAPI(9090)

    if (IP in packet or IPv6 in packet) and UDP in packet: #if IP in packet and UDP in packet:

        pkt_type = "IPv6" if IPv6 in packet else "IPv4"

        # logging
        packets_received += 1


        # Classification the packet

        result = classifier.classify_packet(packet)
        if not result or len(result)==2 or len(result)==1 or len(result)< 3 or result[1] is None:
            #q_cache.put([flowkey_local,packet])
            return
        else:
            
            flow_class = "CG" if result[1] in ('CG_UL', 'CG_DL','CG') else "Other"
            if pkt_type=="IPv4":
                dst_ip = str(packet[IP].dst)
                src_ip = str(packet[IP].src)
                binary_ip_dst = ip_to_bits(str(packet[IP].dst))
                ip_crc16_dst = bits_to_crc16(binary_ip_dst)
                binary_port_dst = port_to_bits(packet[UDP].dport)
                ip_port_concat = binary_ip_dst + binary_port_dst

                flow_id_dst = bits_to_crc16(ip_port_concat)
                unique_flow_flag = add_or_update_entry(flow_id_dst, flow_class, False)
                binary_ip_src = ip_to_bits(str(packet[IP].src))
                ip_crc16_src = bits_to_crc16(binary_ip_src)
                binary_port_src = port_to_bits(packet[UDP].sport)

                port_crc16_src = bits_to_crc16(binary_port_src)
                # port_crc16 = bits_to_crc16(binary_port)  packet[IPv6]

                flow_id_src = ip_crc16_src + port_crc16_src   # flow_id crc using ip & port
                unique_flow_flag = add_or_update_entry(flow_id_src, flow_class, False)
                #print("tag",unique_flow_flag)





            elif  pkt_type=="IPv6":
                dst_ip = str(packet[IPv6].dst)
                src_ip = str(packet[IPv6].src)
                binary_ip_dst = ip_to_bits(str(packet[IPv6].dst))
                binary_port_dst = port_to_bits(packet[UDP].dport)


                ip_port_concat = binary_ip_dst + binary_port_dst
                flow_id_dst = bits_to_crc16(ip_port_concat)
                unique_flow_flag = add_or_update_entry(flow_id_dst, flow_class, False)



                binary_ip_src = ip_to_bits(str(packet[IPv6].src))
                ip_crc16_src = bits_to_crc16(binary_ip_src)
                binary_port_src = port_to_bits(packet[UDP].sport)
                port_crc16_src = bits_to_crc16(binary_port_src)

                flow_id_src = ip_crc16_src + port_crc16_src   # flow_id crc using ip & port
                unique_flow_flag = add_or_update_entry(flow_id_src, flow_class, False)
 





            if flow_class == "CG" and unique_flow_flag: 
                controller.register_write('flow_queue', flow_id_dst, 2)
                
                print(f'DST IP {dst_ip} DST Port {packet[UDP].dport} in Queue 2')
                print(f'SRC IP {src_ip} SRC Port {packet[UDP].sport} in Queue 2')


                counter_CG_class = counter_CG_class + 1
                print(counter_CG_class)
                if pkt_type == "IPv4":
                    CG_class_IPs.append((src_ip.split('.')[0], dst_ip.split('.')[0]))
                else:
                    CG_class_IPs.append(('1', '1'))

                if counter_CG_class >= 5:
                    counter_CG_IP = 0

                    for ips in CG_class_IPs:
                        if int(ips[0]) == CG_first_octet or int(ips[1]) == CG_first_octet:
                            counter_CG_IP = counter_CG_IP + 1

                    rate = (counter_CG_IP / counter_CG_class) * 100
                    print(rate)
                    counter_CG_class = 0
                    CG_class_IPs = []

                    point = (
                        Point("Rating")
                        .tag("ID", id)
                        .field("rate", rate)
                    )
                    client.write(database=database, record=point)



            elif flow_class == "Other" and unique_flow_flag:
                
                controller.register_write('flow_queue', flow_id_dst, 1)
                
                
                print(f'DST IP {dst_ip} DST Port {packet[UDP].dport} in Queue 1')
                print(f'SRC IP {src_ip} SRC Port {packet[UDP].sport} in Queue 1')
            elif unique_flow_flag:
                controller.register_write('flow_queue', flow_id_dst, 0)
                
                
                print(f'DST IP {dst_ip} DST Port {packet[UDP].dport} in Queue 0')
                print(f'SRC IP {src_ip} SRC Port {packet[UDP].sport} in Queue 0')
      


def main():
    global classifier, reset_time
    #config_file = '/home/cls/config.yaml'
    config = load_config(config_file)

    model_path = config['cls_config']['model'][config['cls_config']['model']['selection']]['path']
    SRC_INTERFACE = config['cls_config']['ingress']['interface']
    reset_time = config['cls_config']['lookup_table']['reset_time']
    entry_num = config['cls_config']['lookup_table']['reset_entry_num']
    classifier = PacketClassifier(model_path)

    print('The model in this classifier is ', config['cls_config']['model']['selection'],' loaded from ', model_path)
    print(f'The reset time for lookup table [and model loading!] is {reset_time}')

    print(f"Listening for UDP packets on {SRC_INTERFACE}...")
    sniff(iface=SRC_INTERFACE, prn=forward_packet, store=False)

    print(f"Total packets received: {packets_received}")
    print(f"Total packets forwarded: {packets_forwarded}")

if __name__ == "__main__":
    main()
