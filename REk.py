from Crypto.Cipher import Blowfish
# FSAZ△ write it !!!

"""
目录
数组处理
    array_to_string(arr) 数组输出为连续的字符串，以''内字符分割
    array_hex_to_bytes(arr)
数据格式转换
    str_to_bytes(str)
    bytes_to_str_boom(str)
    str_hex_to_ascii(hex_data)
    
解密
    blowfish_decryption_boom(key, cipher_text)
文件操作
    read_file_line(file_path) 按行返回列表
"""
# 数组处理-----------------------------------------------------------------------------------
def array_to_string(arr):
    # 数组输出为连续的字符串，以''内字符分割
    return ''.join(map(str, arr))

def array_hex_to_bytes(arr):
    # [0xFC, 0xD6, 0x82, 0x33, 0x86, 0x04, ...] -> b'\xfc\xd6\x823\x86..
    return bytes(arr)
# 数据格式转换----------------------------------------------------------------------------------
def str_to_bytes(str):
    try:
        # 尝试将字符串编码为字节串
        bytes_data = str.encode()
        return bytes_data
    except UnicodeEncodeError:
        # 如果编码失败，则手动转换为字节串
        bytes_data = bytes(str, 'utf-8')
        return bytes_data


def bytes_to_str_boom(str):
    try:
        byte_str = eval(str)
        try:
            decoded_str = byte_str.decode('utf-8')
            return decoded_str
        except UnicodeDecodeError as e:
            return 0
    except Exception as e:
        return 0

def str_hex_to_ascii(hex_data):
    # str16->srt
    # 检查并移除前缀 '0x'
    if hex_data.startswith("0x"):
        hex_data = hex_data[2:]

    # 检查并移除后缀 'i64'
    if hex_data.endswith("i64"):
        hex_data = hex_data[:-3]

    # 确保长度为偶数
    if len(hex_data) % 2 != 0:
        raise ValueError("Hex string has an odd length, which is invalid.")

    # 将十六进制字符串转换为 ASCII 字符串
    ascii_string = bytes.fromhex(hex_data).decode('ascii')
    return ascii_string

def endian_Invert(byte_data):
    # 颠倒端序
    return byte_data[::-1]
# 加密-----------------------------------------------------------------------------------------
def blowfish_decryption_boom(key, cipher_text):
    mode = [Blowfish.MODE_ECB,
            Blowfish.MODE_CBC,
            Blowfish.MODE_CFB,
            Blowfish.MODE_OFB,
            Blowfish.MODE_CTR,
            Blowfish.MODE_OPENPGP,
            Blowfish.MODE_EAX]
    decrypted_data = {}
    for i in mode:
        # 初始化Blowfish解密算法
        if i == Blowfish.MODE_CTR:
            nonce = b'\x00' * 4  # 生成一个安全的随机数
            cipher = Blowfish.new(key, i, nonce=nonce)
            print(cipher.decrypt(cipher_text))
        else:
            cipher = Blowfish.new(key, i)
            print(cipher.decrypt(cipher_text))
    return None
# 文件操作-------------------------------------------------------------------------------
def read_file_line(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            # 去除每行末尾的换行符
            lines = [line.strip() for line in lines]
        return lines
    except FileNotFoundError:
        return f"Error: The file at {file_path} was not found."
    except Exception as e:
        return f"Error reading file: {str(e)}"
