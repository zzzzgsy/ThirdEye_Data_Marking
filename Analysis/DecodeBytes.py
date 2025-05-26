import string
# 检查bytes是否大部分都是可打印字符
def is_bytes_mostly_printable(bytes_str: bytes, threshold=0.7) -> bool:
    if len(bytes_str) == 0:
        return False
    printable_count = 0
    for b in bytes_str:
        if b in bytes(string.printable, encoding='ascii'):
            printable_count += 1
    if printable_count / len(bytes_str) < threshold:
        return False
    return True

import unicodedata
# 将bytes用UTF-8解码，使用\x形式替换无法打印的字符，并替换控制字符（不包括回车）
def decode_bytes_utf8(bytes_str: bytes, errors="backslashreplace") -> str:
    decoded_str = bytes_str.decode('utf-8', errors='backslashreplace')
    result = ''
    for ch in decoded_str:
        if ch not in ('\r', '\n') and unicodedata.category(ch)[0] == "C":
            for b in ch.encode('utf-8'):
                hex_b = hex(b)[2:]
                result += '\\x' + '0' * (2 - len(hex_b)) + hex_b
        else:
            result += ch
    return result.replace('\r\n', '\n')

# 将bytes用ascii解码，使用\x形式替换无法打印的字符，并替换控制字符
def decode_bytes_ascii(bytes_str: bytes, errors="backslashreplace") -> str:
    decoded_str = bytes_str.decode('ascii', errors='backslashreplace')
    result = ''
    for ch in decoded_str:
        if unicodedata.category(ch)[0] == "C":
            hex_b = hex(ord(ch))[2:]
            result += '\\x' + '0' * (2 - len(hex_b)) + hex_b
        else:
            result += ch
    return result

# 根据bytes中可打印字符的数量，对bytes进行解码
# utf8用于打印可打印字符串（通常是人可以阅读的），ascii用于打印不可打印的（通常是加密、编码后的）数据
def decode_bytes(bytes_str: bytes) -> str:
    if is_bytes_mostly_printable(bytes_str):
        return decode_bytes_utf8(bytes_str)
    else:
        return decode_bytes_ascii(bytes_str)

# 从data中提取UTF-8编码的可打印字符串
def extract_printable_utf8(data: bytes, min_len=6) -> list[str]:
    # replace模式会将编码失败的字符替换为�，b'\xef\xbf\xbd'
    decoded_str = data.decode('utf-8', errors='replace')
    printable_str_list = []
    temp_str = ''
    for ch in decoded_str:
        if ch.encode('utf-8') == b'\xef\xbf\xbd' or \
        (ch not in ('\r', '\n') and unicodedata.category(ch)[0] == "C"):
            if len(temp_str.encode('utf-8')) >= min_len:
                printable_str_list.append(temp_str)
            temp_str = ''
        else:
            temp_str += ch
    if len(temp_str.encode('utf-8')) >= min_len:
        printable_str_list.append(temp_str)
    return printable_str_list