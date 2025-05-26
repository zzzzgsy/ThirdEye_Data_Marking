import os
import json

# 用于过滤加密函数调用信息的函数
def __CryptInfoFilter(crypt_info: dict):
    method_black_list = ["percentdecode", "urlencode", "encodedquery"]
    if crypt_info['method_name'].lower() in method_black_list:
        return False
    class_method_black_list = [("javax.crypto.Cipher", "init-key"), ("javax.crypto.spec.SecretKeySpec", "$new")]
    # class_method_black_list.append(("javax.crypto.Cipher", "update"))
    if (crypt_info['class_name'], crypt_info['method_name']) in class_method_black_list:
        return False
    return True

# 读取加密函数调用信息，返回一个list
def read_crypt_info(pkg_name: str) -> list[dict]:
    outdir = os.path.join("out/", pkg_name)
    crypt_list = []
    with open(os.path.join(outdir, 'crypt.txt')) as f:
        for line in f:
            crypt_list.append(json.loads(line))
    crypt_list = list(filter(__CryptInfoFilter, crypt_list))
    return crypt_list

import base64
# 判断bytes是否为有一定长度的base64
def isBase64(s: bytes, min_len=18)->bool:
    try:
        return base64.b64encode(base64.b64decode(s)) == s and len(base64.b64decode(s)) >= min_len
    except Exception:
        return False

# 函数调用信息中，字符串/数据串类型的参数/返回值，会以base64形式存储，而对于整数，通常为字符串类型的数字
# 判断函数调用信息中的参数/返回值，是否表示一个字符串/数据串类型
def isArgStr(arg) -> bool:
    return isinstance(arg, str) and isBase64(arg.encode('utf-8'))

# 判断函数调用信息是否与当前正在构建的函数调用组相关
def isCryptInfoRelated(crypt_info: dict, related_str: set[str]) -> bool:
    result = False
    for arg in crypt_info['args']:
        if isArgStr(arg) and arg in related_str:
            result = True
            break
    if isArgStr(crypt_info['ret']) and crypt_info['ret'] in related_str:
        result = True
    return result

# 将相关的函数调用聚合到一组中
def merge_crypt_info(crypt_list: list[dict]) -> list[list[dict]]:
    crypt_groups = []
    while len(crypt_list) > 0:
        group = []  # 每次循环，构建一组相关的加密算法调用
        related_str = set() # 本次构建中，在加密算法的参数和返回值中出现过的字符串
        crypt_info = crypt_list.pop(0)  # 先取出一个加密算法调用
        group.append(crypt_info)
        # 将这个函数调用的字符串类型的参数和返回值加入related_str中
        for arg in crypt_info['args']:
            if isArgStr(arg):
                related_str.add(arg)
        if isArgStr(crypt_info['ret']):
            related_str.add(crypt_info['ret'])
        
        group_updated_flag = True
        while group_updated_flag:
            # 如果group_updated_flag为True，表示在本次遍历中，group的内容发生了更新
            # 因此需要再遍历一遍函数调用，直到group没有发生更新为止
            group_updated_flag = False
            i = 0
            while i < len(crypt_list):
                crypt_info = crypt_list[i]
                # 如果当前crypt_info不和正在构建的group相关，那么继续看下一个函数调用
                if not isCryptInfoRelated(crypt_info, related_str):
                    i += 1
                    continue
                # 如果相关，则将当前crypt_info从crypt_list中取出，加入group，并更新related_str
                crypt_info = crypt_list.pop(i)
                group.append(crypt_info)
                group_updated_flag = True
                for arg in crypt_info['args']:
                    if isArgStr(arg):
                        related_str.add(arg)
                if isArgStr(crypt_info['ret']):
                    related_str.add(crypt_info['ret'])
            # end 遍历一遍函数调用
        # end 本次构建group
        crypt_groups.append(sorted(group, key=lambda x: x['ts']))
    # end 所有函数调用信息均加入到了crypt_groups当中
    return crypt_groups


from .DataUnit import DataUnit
# 检查参数或返回值（以及其各种编码形式）是否能在DataUnit（某个时刻传输的数据）中能找到
def isArgInDataUnit(arg: str, dataunit: DataUnit) -> bool:
    if not isArgStr(arg):
        return False
    arg_bytes = base64.b64decode(arg)
    result = arg_bytes in dataunit.data
    result = result or arg_bytes.replace(b'/', b'\\/') in dataunit.data
    result = result or base64.b64encode(arg_bytes) in dataunit.data
    if isBase64(arg_bytes):
        result = result or base64.b64decode(arg_bytes) in dataunit.data
    result = result or arg_bytes.hex().encode('utf-8') in dataunit.data
    for sep in [',', ' ', '-']:
        result = result or arg_bytes.hex(sep).encode('utf-8') in dataunit.data
    return result

# 搜索所有和group里函数调用相关的dataunit
def search_group_related_dataunits(group: list[dict], dataunit_list: list[DataUnit]) -> list[DataUnit]:
    result = set()
    for dataunit in dataunit_list:
        is_related_dataunit = False
        for crypt_info in group:
            for arg in crypt_info['args']:
                if isArgInDataUnit(arg, dataunit):
                    is_related_dataunit = True
            if isArgInDataUnit(crypt_info['ret'], dataunit):
                is_related_dataunit = True
        if is_related_dataunit:
            result.add(dataunit)
    return sorted(result, key=lambda x: x.timestamp)

# 检查字符串是否为JSON格式
def is_json(s):
    try:
        json.loads(s)
    except ValueError as e:
        return False
    return True

from .DecodeBytes import decode_bytes
# 传入base64格式数据，尝试转换成可打印字符串
def Base64toPrintableStr(s: str) -> str:
    if not isBase64(s.encode('utf-8'), min_len=10):
        return ""
    try:
        result = decode_bytes(base64.b64decode(s))
        if is_json(result):
            result = json.dumps(json.loads(result), indent='\t')
        return result
    except AttributeError:
        return ""

import textwrap
# 将函数调用信息转换为可打印字符串形式
def crypt_info2str(crypt_info: dict) -> str:
    result = "Timestamp: " + str(crypt_info['ts']) + "\n"
    result += "Class: " + crypt_info['class_name'] + "\n"
    result += "Method: " + crypt_info['method_name'] + "\n"
    result += "Args:\n"
    for arg in crypt_info['args']:
        printable_str = Base64toPrintableStr(str(arg))
        if printable_str:
            result += "*****\n" + printable_str + "\n*****\n"
        else:
            result += str(arg) + "\n"
    result += "Ret:\n"
    printable_str = Base64toPrintableStr(str(crypt_info['ret']))
    if printable_str:
        result += "*****\n" + printable_str + "\n*****\n"
    elif not str(crypt_info['ret']):
        result += "null"+ "\n"
    else:
        result += str(crypt_info['ret']) + "\n"
    result += "StackTrace:\n"
    if 'stackTrace' in crypt_info:
        result += textwrap.indent(base64.b64decode(crypt_info['stackTrace']).decode('utf-8'), "\t") + "\n"
    else:
        result += textwrap.indent("null", "\t") + "\n"
    return result