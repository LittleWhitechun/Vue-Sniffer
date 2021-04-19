import ctypes
from ctypes import *
from winpcapy import *
import time
import sys
import string

u_short = c_ushort
u_char = c_ubyte
u_int = c_int


class mac_address(Structure):
    _fields_ = [("byte1", u_char),
                ("byte2", u_char),
                ("byte3", u_char),
                ("byte4", u_char),
                ("byte5", u_char),
                ("byte6", u_char)]


class eth_header(BigEndianStructure):
    _fields_ = [("destination_mac", mac_address),
                ("source_mac", mac_address),
                ("type", u_short)]


class ip_address(Structure):
    _fields_ = [("byte1", u_char),
                ("byte2", u_char),
                ("byte3", u_char),
                ("byte4", u_char)]


class ip_header(BigEndianStructure):
    _fields_ = [("ver_ihl", u_char),  # 头部长度
                ("tos", u_char),  # TOS服务类行
                ("tlen", u_short),  # 包总长
                ("identification", u_short),  # 标识
                ("flags_fo", u_short),  # 片位移
                ("ttl", u_char),  # TTL 生存时间
                ("proto", u_char),  # 协议
                ("crc", u_short),  # 校验和
                ("saddr", ip_address),  # 源IP
                ("daddr", ip_address),  # 目的IP
                ("op_pad", u_int)]


class tcp_header(BigEndianStructure):
    _fields_ = [("source_port", u_short),
                ("destination_port", u_short),
                ("seq", u_int),
                ("ack", u_int),
                ("flags", u_short),
                ("window", u_short),
                ("checksum", u_short),
                ("urgent", u_short),
                ("options", u_int)]


# Packet capture function
PHAND = CFUNCTYPE(None, POINTER(c_ubyte), POINTER(pcap_pkthdr), POINTER(c_ubyte))


## Callback function which is called for every new packet
def _packet_handler(param, header, pkt_data):
    v_pkt_data = ctypes.cast(pkt_data, ctypes.c_void_p)
    v_ip_header = ctypes.c_void_p(v_pkt_data.value + 14)
    pih = ctypes.cast(ctypes.c_void_p(v_pkt_data.value + 14), ctypes.POINTER(ip_header))
    ih = ctypes.cast(ctypes.c_void_p(v_pkt_data.value + 14), ctypes.POINTER(ip_header)).contents
    eh = ctypes.cast(ctypes.c_void_p(v_pkt_data.value), ctypes.POINTER(eth_header)).contents

    ip_len = (ih.ver_ihl & 0xf) * 4
    ip_ver = (ih.ver_ihl & 0xf0) >> 4
    th = ctypes.cast(ctypes.cast(pih, ctypes.c_void_p).value + ip_len,
                     ctypes.POINTER(tcp_header)).contents
    if (ih.proto == 6):
        print("{}:{}:{}:{}:{}:{} -> {}:{}:{}:{}:{}:{}".format(hex(eh.source_mac.byte1), hex(eh.source_mac.byte2),
                                                              hex(eh.source_mac.byte3), hex(eh.source_mac.byte4),
                                                              hex(eh.source_mac.byte5), hex(eh.source_mac.byte6),
                                                              hex(eh.destination_mac.byte1),
                                                              hex(eh.destination_mac.byte2),
                                                              hex(eh.destination_mac.byte3),
                                                              hex(eh.destination_mac.byte4),
                                                              hex(eh.destination_mac.byte5),
                                                              hex(eh.destination_mac.byte6)))
        print("{}.{}.{}.{}:{} -> {}.{}.{}.{}:{} Protocol: {} IP-version:{}".format(ih.saddr.byte1, ih.saddr.byte2,
                                                                                   ih.saddr.byte3,
                                                                                   ih.saddr.byte4, th.source_port,
                                                                                   ih.daddr.byte1,
                                                                                   ih.daddr.byte2, ih.daddr.byte3,
                                                                                   ih.daddr.byte4,
                                                                                   th.destination_port, ih.proto,
                                                                                   ip_ver))


def get_ad():
    i = 0
    d = alldevs.contents
    print('------------')
    print(d)
    while d:
        i = i + 1
        print("%d. %s" % (i, d.name))
        print(" (%s)\n" % (d.description))
        if d.next:
            d = d.next.contents
        else:
            d = False
    inum = input("Enter the interface number (1-%d):" % (i))

    inum = int(inum)
    d = alldevs
    ## Get Selected adaptor
    for i in range(0, inum - 1):
        d = d.contents.next
    return d.contents


packet_handler = PHAND(_packet_handler)

alldevs = POINTER(pcap_if_t)()
errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)

if (pcap_findalldevs(byref(alldevs), errbuf) == -1):
    print("Error in pcap_findalldevs: %s\n" % errbuf.value)
    sys.exit(1)

## 获取设备
d = get_ad()
adhandle = pcap_open_live(d.name,  # 设备名
                          65536,  # 65535可以保证捕获到不同层上的所有内容
                          1,  # 1为指定网卡为混杂模式
                          1000,  # 超时时间
                          errbuf)

print("\nStarting to listen on %s...\n" % (d.description))

## 获取数据包
pcap_loop(adhandle
          , 50, packet_handler, None)
pcap_close(adhandle)
