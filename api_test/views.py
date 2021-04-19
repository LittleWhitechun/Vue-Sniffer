from django.shortcuts import render
from django.views.decorators.http import require_http_methods
from django.core import serializers
from django.http import JsonResponse
import json


from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, Ether

import ctypes
from ctypes import *
from winpcapy import *
import time
import sys
import string

u_short = c_ushort
u_char = c_ubyte
u_int = c_int

# Create your views here.

capture_flag = False



def call_back_packet(pkt):
    # print('get packet[Ether]:')
    # print(pkt.payload)
    packet_info = {'src_mac': '', 'dst_mac': '', 'mac_type': '', 'src_ip': '', 'dst_ip': '', 'ip_type': '',
                   'src_port': '', 'dst_port': '', 'tcp_type': '', 'udp_type': '', 'length': '', 'content': '',
                   'time': '', 'type': '','ip_len':'','ip_ttl':'','chksum':''}
    packet_time = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
    # print('src:' + pkt[Ether].src)
    # print('dst:' + pkt[Ether].dst)
    packet_info['time'] = packet_time
    packet_info['src_mac'] = pkt[Ether].src
    packet_info['dst_mac'] = pkt[Ether].dst
    types = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x88cc: 'LLDP', 0x891D: 'TTE'}
    proto = types[pkt[Ether].type]
    packet_info['mac_type'] = types[pkt[Ether].type]
    packet_info['content'] = hexdump(pkt, dump=True)
    packet_info['length'] = len(pkt)

    if packet_info['mac_type'] == 'ARP':
        packet_info['type'] = 'ARP'
        packet_info['source'] = packet_info['src_mac']
        packet_info['destination'] = 'Broadcast'
        return packet_info

    if IP in pkt:
        ip_protos = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6', 50: 'ESP',
                     89: 'OSPF'}
        src = pkt[IP].src
        dst = pkt[IP].dst
        packet_info['src_ip'] = src
        packet_info['dst_ip'] = dst
        ip_proto = pkt[IP].proto
        packet_info['ip_type'] = ip_protos[ip_proto]
        packet_info['type'] = packet_info['ip_type']
        packet_info['ip_len'] = pkt[IP].len
        packet_info['ip_ttl'] = pkt[IP].ttl
        packet_info['source'] = packet_info['src_ip']
        packet_info['destination'] = packet_info['dst_ip']
        # print('---------IP-------------')
        # print('src:' + src + ',dst:' + dst)
    if packet_info['mac_type'] == 'IPv6':
        packet_info['type'] = 'IPv6'
    #     return packet_info

    if TCP in pkt:
        packet_info['type'] = 'TCP'
        print('tcp开头现在是：' + types[pkt[Ether].type])
        protos_tcp = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH', 25: 'SMTP'}
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        packet_info['src_port'] = sport
        packet_info['dst_port'] = dport
        proto2 = ''
        if sport in protos_tcp:
            proto2 = protos_tcp[sport]
        elif dport in protos_tcp:
            proto2 = protos_tcp[dport]
        if proto2:
            print(proto2)
            packet_info['type'] = proto2
        packet_info['tcp_seq'] =pkt[TCP].seq
        packet_info['tcp_ack'] = pkt[TCP].ack
        packet_info['tcp_window'] = pkt[TCP].window
        packet_info['tcp_chksum'] = pkt[TCP].chksum
    if UDP in pkt:
        packet_info['type'] = 'UDP'
        proto3 = ''
        if pkt[UDP].sport == 53 or pkt[UDP].dport == 53:
            proto3 = 'DNS'
        packet_info['udp_type'] = proto3
        if 'len' in pkt[UDP]:
            packet_info['udp_len'] = pkt[UDP].len
        if 'chksum' in pkt[UDP]:
            packet_info['chksum'] = pkt[UDP].chksum
    # packet_info['type'] = pkt.payload.proto
    # info = pkt.summary()  # 信息
    # print("length:{};info:{}".format(length, info))

    lines = pkt.show(dump=True).split('\n')
    for line in lines:
        if line.startswith('#'):
            line = line.strip('# ')  # 删除#
    if IP in pkt:
        ip = pkt[IP]
        # ip.show()
    # print(hexdump(pkt, dump=True))

    if 'source' not in  packet_info:
        packet_info['source'] = packet_info['src_mac']
        packet_info['destination'] = packet_info['dst_mac']

    return packet_info


@require_http_methods(["GET"])
def get_packet(request):
    response = {}
    # print('get packet')
    try:
        device_name = request.GET.get('device')
        filter = request.GET.get('filter')
        # print('device:' + device_name)
        print('filter:' + filter)
        # print('start sniff')
        pcap = sniff(count=1,filter=filter, iface=device_name)
        packet_content = {}
        # print(pcap)
        # print(pcap[0])
        for i in pcap:
            print('get packet:')
            types = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x88cc: 'LLDP', 0x891D: 'TTE'}
            packet_content = call_back_packet(i)
            print(types[i[Ether].type])
        # print('---------------------' + pcap[Ether].type)
        response = packet_content
        # print('---------------------' + response['mac_type'])
        response['msg'] = 'success'
        response['error_num'] = 0
    except  Exception as e:
        response = {}
        response['msg'] = str(e)
        response['error_num'] = 1
    return JsonResponse(response)

@require_http_methods(["GET"])
def get_device(arg):
    response = {}
    response['device'] = []
    for iface_name in sorted(ifaces.data.keys()):
        dev = ifaces.data[iface_name]
        mac = conf.manufdb._resolve_MAC(str(dev.mac))
        name = str(dev.name).ljust(4)
        ip = dev.ip
        mac = mac.upper()
        response['device'].append({'name':name,'mac':mac,'ip':ip})
    print(response)
    return JsonResponse(response)