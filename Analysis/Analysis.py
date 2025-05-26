from .CryptUtils import *
from .DataUnit import *
from .DecodeBytes import extract_printable_utf8
import string
import random
from pathlib import Path
# 综合分析加密函数调用和mitmproxy抓包结果，存储到文件中


# 提取并可视化所有流量，包括未加密关联的部分
def visualize_mitm_data(mitm_unit: MitmDataUnit, outdir: str):
    # 提取关键信息
    client_ip, client_port = mitm_unit.flow.client_conn.sockname
    target_host = mitm_unit.flow.request.host
    url = mitm_unit.flow.request.pretty_url
    method = mitm_unit.flow.request.method
    headers = mitm_unit.flow.request.headers
    content = mitm_unit.flow.request.text

    # 组织写入文件的内容
    output_str = f"Source: {client_ip}:{client_port}\n"
    output_str += f"Target: {target_host}\n"
    output_str += f"URL: {url}\n"
    output_str += f"Method: {method}\n"
    output_str += f"Headers:\n{headers}\n"
    output_str += f"Content:\n{content}\n"

    # 写入文件
    filename = f"{mitm_unit.flow.request.timestamp_start}_{random.randint(100000, 999999)}.txt"
    Path(outdir).mkdir(parents=True, exist_ok=True)
    with open(os.path.join(outdir, filename), "w", encoding='utf-8') as f:
        f.write(output_str)

# 修改分析流程：对未加密流量进行可视化展示
# def analyse_crypt_mitm(pkg_name: str):
#     outdir = os.path.join("out/", pkg_name, 'crypt_mitm')
#     crypt_list = read_crypt_info(pkg_name)
#     crypt_groups = merge_crypt_info(crypt_list)
#     mitm_list = read_mitm_list(pkg_name)

#     # 已关联的流量集合
#     associated_mitm_set = set()

#     for group in crypt_groups:
#         related_mitm_list = search_group_related_dataunits(group, mitm_list)
#         associated_mitm_set.update(related_mitm_list)

#         # 构建加密关联输出文件
#         output_str = ''
#         for crypt_info in group:
#             output_str += crypt_info2str(crypt_info)
#             output_str += '\n' + '-' * 60 + '\n'
#         url_set = set()
#         for mitm_unit in related_mitm_list:
#             output_str += '+' * 60 + '\n'
#             output_str += str(mitm_unit) + '\n'
#             url_set.add(mitm_unit.flow.request.host)

#         filename = str(group[0]['ts']) + ''.join(random.choice(string.digits) for _ in range(6))
#         for url in url_set:
#             Path(os.path.join(outdir, url)).mkdir(parents=True, exist_ok=True)
#             with open(os.path.join(outdir, url, filename), "w", encoding='utf-8') as f:
#                 f.write(output_str)

#     # 对未关联加密的流量进行可视化
#     unassociated_mitm_list = [unit for unit in mitm_list if unit not in associated_mitm_set]
#     for mitm_unit in unassociated_mitm_list:
#         visualize_mitm_data(mitm_unit, os.path.join(outdir, 'unassociated'))


def analyse_crypt_mitm(pkg_name: str):
    outdir = os.path.join("out/", pkg_name, 'crypt_mitm')
    crypt_list = read_crypt_info(pkg_name)
    crypt_groups = merge_crypt_info(crypt_list)
    mitm_list = read_mitm_list(pkg_name)
    for group in crypt_groups:
        related_mitm_list = search_group_related_dataunits(group, mitm_list)
        # 构建写入文件的字符串内容
        output_str = ''
        for crypt_info in group:
            output_str += crypt_info2str(crypt_info)
            output_str += '\n' + '-' * 60 + '\n'
        url_set = set()
        mitm_unit: MitmDataUnit
        for mitm_unit in related_mitm_list:
            output_str += '+' * 60 + '\n'
            output_str += str(mitm_unit) + '\n'
            url_set.add(mitm_unit.flow.request.host)
        # 将结果写入文件
        filename = str(group[0]['ts']) + \
        ''.join(random.choice(string.digits) for _ in range(6))

        for url in url_set:
            Path(os.path.join(outdir, url)).mkdir(parents=True, exist_ok=True)
            with open(os.path.join(outdir, url, filename), "w", encoding='utf-8') as f:
                f.write(output_str)

# 综合分析加密函数调用和pcap抓包结果，存储到文件中
def analyse_crypt_pcap(pkg_name: str):
    outdir = os.path.join("out/", pkg_name, 'crypt_pcap')
    crypt_list = read_crypt_info(pkg_name)
    crypt_groups = merge_crypt_info(crypt_list)
    pcap_list = read_pcap_list(pkg_name)
    for group in crypt_groups:
        related_pcap_list = search_group_related_dataunits(group, pcap_list)
        # 构建写入文件的字符串内容
        output_str = ''
        for crypt_info in group:
            output_str += crypt_info2str(crypt_info)
            output_str += '\n' + '-' * 60 + '\n'
        url_set = set()
        pcap_unit: PcapDataUnit
        for pcap_unit in related_pcap_list:
            output_str += '+' * 60 + '\n'
            output_str += str(pcap_unit) + '\n'
            url_set.add(socket.inet_ntoa(pcap_unit.packet.data.dst)+"-"+str(pcap_unit.packet.data.data.dport))
        # 将结果写入文件
        filename = str(group[0]['ts']) + \
        ''.join(random.choice(string.digits) for _ in range(6))

        for url in url_set:
            Path(os.path.join(outdir, url)).mkdir(parents=True, exist_ok=True)
            with open(os.path.join(outdir, url, filename), "w", encoding='utf-8') as f:
                f.write(output_str)

# 提取pcap抓包结果中的可打印字符串，存储到文件中
def extract_pcap_printable(pkg_name: str):
    outdir = os.path.join("out/", pkg_name, 'printable_pcap')
    Path(outdir).mkdir(parents=True, exist_ok=True)
    pcap_list = read_pcap_list(pkg_name)
    for pcap_unit in pcap_list:
        printable_str_list = extract_printable_utf8(pcap_unit.data)
        if len(printable_str_list) == 0:
            continue
        output_str = pcap_unit.headers_str() + '\n'
        for printable_str in printable_str_list:
            output_str += '-' * 30 + '\n' + printable_str.replace('\r\n', '\n') + '\n'
        output_str += '*' * 60 + '\n'
        filename = socket.inet_ntoa(pcap_unit.packet.data.dst)+"-"+str(pcap_unit.packet.data.data.dport)
        with open(os.path.join(outdir, filename), "a", encoding='utf-8') as f:
            f.write(output_str)

# 综合分析加密函数调用和APP写文件行为，存储到文件中
def analyse_crypt_fileio(pkg_name: str):
    outdir = os.path.join("out/", pkg_name, 'crypt_fileio')
    crypt_list = read_crypt_info(pkg_name)
    crypt_groups = merge_crypt_info(crypt_list)
    file_list = read_fs_list(pkg_name, ('write'))
    for group in crypt_groups:
        related_file_list = search_group_related_dataunits(group, file_list)
        # 构建写入文件的字符串内容
        output_str = ''
        for crypt_info in group:
            output_str += crypt_info2str(crypt_info)
            output_str += '\n' + '-' * 60 + '\n'
        file_set = set()
        file_unit: FileIODataUnit
        for file_unit in related_file_list:
            output_str += '+' * 60 + '\n'
            output_str += str(file_unit) + '\n'
            file_set.add(file_unit.path)
        # 将结果写入文件
        filename = str(group[0]['ts']) + \
        ''.join(random.choice(string.digits) for _ in range(6))

        for file in file_set:
            Path(os.path.join(outdir, file)).mkdir(parents=True, exist_ok=True)
            with open(os.path.join(outdir, file, filename), "w", encoding='utf-8') as f:
                f.write(output_str)

# 提取文件读写中的可打印字符串，存储到文件中
def extract_fileio_printable(pkg_name: str):
    outdir = os.path.join("out/", pkg_name, 'printable_file')
    Path(outdir).mkdir(parents=True, exist_ok=True)
    file_list = read_fs_list(pkg_name)
    for file_unit in file_list:
        printable_str_list = extract_printable_utf8(file_unit.data)
        if len(printable_str_list) == 0:
            continue
        output_str = file_unit.headers_str() + '\n'
        for printable_str in printable_str_list:
            output_str += '-' * 30 + '\n' + printable_str.replace('\r\n', '\n') + '\n'
        output_str += '*' * 60 + '\n'
        filename = file_unit.path.replace('/', '-') + '.txt'
        with open(os.path.join(outdir, filename), "a", encoding='utf-8') as f:
            f.write(output_str)