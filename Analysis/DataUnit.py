from .DecodeBytes import decode_bytes, decode_bytes_utf8

# 表示在某个时刻传输的数据
class DataUnit:
    def __init__(self, databytes: bytes, timestamp: float):
        self.data = databytes
        self.timestamp = timestamp

from mitmproxy import http
from mitmproxy import io
import os
from urllib.parse import urlparse
from urllib.parse import parse_qs
import textwrap
# 表示一项mitmproxy包
class MitmDataUnit(DataUnit):
    def __init__(self, flow: http.HTTPFlow):
        none2empty = lambda x: b'' if x is None else x
        self.data = none2empty(flow.request.path.encode('utf-8')) + \
                    none2empty(bytes(flow.request.headers)) + \
                    none2empty(flow.request.raw_content)
        self.timestamp = flow.request.timestamp_start
        self.flow = flow
    
    def __str__(self):
        result = "Timestamp: " + str(self.timestamp) + "\n"
        result += repr(self.flow.request) + "\n"
        result += "Scheme: " + self.flow.request.scheme + "\n"
        result += self.flow.request.http_version + "\n"
        result += decode_bytes_utf8(bytes(self.flow.request.headers)) + "\n"
        result += "Query:\n"
        parsed_path = urlparse(self.flow.request.path)
        for key, val in parse_qs(parsed_path.query).items():
            result += textwrap.indent(key + str(val), "\t") + "\n"
        result += "Content:\n"
        result += decode_bytes(self.flow.request.raw_content) + "\n"
        return result


# 从mitmproxy的dump文件读取MitmDataUnit
def read_mitm_list(pkg_name: str) -> list[MitmDataUnit]:
    mitm_list = []
    outdir = os.path.join("out/", pkg_name)
    with open(os.path.join(outdir, 'mitmdump'), 'rb') as f:
        freader = io.FlowReader(f)
        for f in freader.stream():
            if isinstance(f, http.HTTPFlow):
                mitm_list.append(MitmDataUnit(f))
    return mitm_list


import dpkt
import socket
import json
# 表示一项tcpdump抓取的pcap文件中的数据包
class PcapDataUnit(DataUnit):
    def __init__(self, packet: dpkt.ethernet.Ethernet, timestamp: float):
        self.data = b''
        if type(packet.data) == dpkt.ip.IP:
            self.data = packet.data.data.data
        self.timestamp = timestamp
        self.packet = packet
    
    def __str__(self):
        if type(self.packet.data) == dpkt.ip.IP and \
        type(self.packet.data.data) not in {dpkt.icmp.ICMP}:
            result = self.headers_str() + "\n"
            result += "Data:\n" + "*" * 60 + "\n"
            result += decode_bytes(self.data) + "\n" + "*" * 60
            return result
        return ""
    
    def headers_str(self) -> str:
        if type(self.packet.data) == dpkt.ip.IP and \
        type(self.packet.data.data) not in {dpkt.icmp.ICMP}:
            result = "Timestamp: " + str(self.timestamp) + "\n"
            result += "Protocol: " + self.packet.data.get_proto(self.packet.data.p).__name__ + "\n"
            result += "Src: " + socket.inet_ntoa(self.packet.data.src)+":"+str(self.packet.data.data.sport) + "\n"
            result += "Dst: " + socket.inet_ntoa(self.packet.data.dst)+":"+str(self.packet.data.data.dport)
            return result
        return ""

# 从tcpdump抓取的pcap文件读取PcapDataUnit
def read_pcap_list(pkg_name: str) -> list[PcapDataUnit]:
    pcap_list = []
    outdir = os.path.join("out/", pkg_name)
    conn_frida_datalist: list[str]
    conn_frida_datalist = [] # Frida挂钩得到的socket通信信息
    local_addrs = set() # APP网络通信的src地址
    if os.path.exists(os.path.join(outdir, 'conn.txt')):
        with open(os.path.join(outdir, 'conn.txt'), 'r') as f:
            conn_frida_datalist += f.readlines()
    # 读取conn.txt文件，获取到所有APP网络通信的src地址:端口，存放到local_addrs
    for conn_data in conn_frida_datalist:
        conn_json = json.loads(conn_data.replace("'", '"'))
        local_addr: str
        local_addr = conn_json["java"]["local_address"] if "java" in conn_json \
            else conn_json["native"]["local_address"]
        local_addrs.add(local_addr.replace("::ffff:", "").replace("/", ""))
    if len(local_addrs) == 0:
        return []
    # 读取tcpdump抓取的pcap文件
    # with open(os.path.join(outdir, 'tcpdump.pcap'), 'rb') as f:
    #     for ts, buf in dpkt.pcap.Reader(f):
    #         # packet: Ethernet
    #         # packet.data: IP
    #         # packet.data.data: TCP/UDP
    #         # packet.data.data.data: bytes
    #         packet = dpkt.ethernet.Ethernet(buf)
    #         if type(packet.data) == dpkt.ip.IP and type(packet.data.data) not in {dpkt.icmp.ICMP, dpkt.igmp.IGMP}:
    #             src_addr = socket.inet_ntoa(packet.data.src)+":"+str(packet.data.data.sport)
    #             # 根据Frida挂钩得到的src地址，以及pcap中dst的IP地址和端口，作一个简单的过滤
    #             if src_addr in local_addrs and \
    #             int(packet.data.data.dport) not in (53, 0) and \
    #             not (packet.data.dst[0] == 255 or packet.data.dst[0] in range(224, 240)):
    #                 pcap_list.append(PcapDataUnit(packet, ts))

    # with open(os.path.join(outdir, 'clean.pcap'), 'rb') as f:
    #     for ts, buf in dpkt.pcap.Reader(f):
    #         try:
    #             packet = dpkt.ethernet.Ethernet(buf)
    #             if type(packet.data) == dpkt.ip.IP and type(packet.data.data) not in {dpkt.icmp.ICMP, dpkt.igmp.IGMP}:
    #                 src_addr = socket.inet_ntoa(packet.data.src)+":"+str(packet.data.data.split)
    #                 # 根据Frida挂钩得到的src地址，以及pcap中dst的IP地址和端口，作一个简单的过滤
    #                 if src_addr in local_addrs and \
    #                 int(packet.data.data.dport) not in (53, 0) and \
    #                 not (packet.data.dst[0] == 255 or packet.data.dst[0] in range(224, 240)):
    #                     pcap_list.append(PcapDataUnit(packet, ts))
    #         except dpkt.dpkt.NeedData:
    #             # 忽略解析错误，继续处理下一条数据包
    #             continue
    # return pcap_list

    with open(os.path.join(outdir, 'clean.pcap'), 'rb') as f:
        for ts, buf in dpkt.pcap.Reader(f):
            try:
                packet = dpkt.ethernet.Ethernet(buf)
                if isinstance(packet.data, dpkt.ip.IP):
                    ip = packet.data  # IP layer
                    transport_layer = ip.data
                    
                    # Check if it's a TCP or UDP packet before accessing sport and dport
                    if isinstance(transport_layer, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                        src_addr = socket.inet_ntoa(ip.src) + ":" + str(transport_layer.sport)
                        dst_addr = socket.inet_ntoa(ip.dst) + ":" + str(transport_layer.dport)

                        # 根据Frida挂钩得到的src地址，以及pcap中dst的IP地址和端口，作一个简单的过滤
                        if src_addr in local_addrs and \
                           int(transport_layer.dport) not in (53, 0) and \
                           not (ip.dst[0] == 255 or ip.dst[0] in range(224, 240)):
                            pcap_list.append(PcapDataUnit(packet, ts))
            except dpkt.dpkt.NeedData:
                # 忽略解析错误，继续处理下一条数据包
                continue
            except Exception as e:
                print(f"Error processing packet: {e}")
                continue
    return pcap_list
    


import json
import base64
# 表示一次文件读写操作的数据
class FileIODataUnit(DataUnit):
    def __init__(self, json_dict: dict):
        self.timestamp: float
        self.function: str
        self.data: bytes
        self.path: str

        self.timestamp = json_dict['ts']
        self.function = json_dict['function']
        if self.function in ('read', 'write'):
            self.path = json_dict['path']
            self.data = base64.b64decode(json_dict['data'])
        else:
            self.data = ''
    
    def __str__(self):
        result = self.headers_str() + "\n"
        result += "Data:\n" + "*" * 60 + "\n"
        result += decode_bytes(self.data) + "\n" + "*" * 60
        return result

    def headers_str(self) -> str:
        result = "Timestamp: " + str(self.timestamp) + "\n"
        result += self.function.upper()
        if self.function in ('read', 'write'):
            result += " " + self.path
        return result

# 从fs.txt读取文件读写操作
def read_fs_list(pkg_name: str, function_range: tuple[str]=('read', 'write')) -> list[FileIODataUnit]:
    outdir = os.path.join("out/", pkg_name)
    fs_list = []
    with open(os.path.join(outdir, 'fs.txt')) as f:
        for line in f:
            fs_info = json.loads(line)
            if fs_info['function'] in function_range:
                fs_list.append(FileIODataUnit(fs_info))
    return fs_list