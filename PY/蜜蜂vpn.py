import base64
import json
import time
import requests
from requests.exceptions import HTTPError, RequestException
from pathlib import Path
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

key = b'ks9KUrbWJj46AftX'
iv = b'ks9KUrbWJj46AftX'

# 获取iPhone可用的Documents目录
docs_dir = str(Path.home() / "Documents")
output_file = os.path.join(docs_dir, "蜜蜂.txt")

requests.packages.urllib3.disable_warnings()
session = requests.Session()

COLOR_RESET = '\033[0m'
COLOR_NEW = '\033[92m'
COLOR_DUP = '\033[91m'

def decrypt_aes_cbc_nopadding(encoded_message, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    encrypted_message = base64.b64decode(encoded_message)
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message

def decode_vmess(vmess_str):
    if vmess_str.startswith('vmess://'):
        b64_encoded = vmess_str[8:]
    else:
        b64_encoded = vmess_str
    decoded_bytes = base64.b64decode(b64_encoded)
    decoded_str = decoded_bytes.decode('utf-8')
    json_data = json.loads(decoded_str)
    return json_data

def get_id_name_list():
    url = ("https://www.md40gf.info:20000/myapi/apinodelist?level=2&proto=v2&platform=android"
           "&code=H7XDMX&token=amSTaWVnkZWOk2xwb2lqapOfbGRplWiRYW2Yk5NqmWVjZJE==&isvip=true&unlimit=true")
    try:
        response = session.get(url, verify=False)
        response.raise_for_status()
        data = response.json()
        seen = set()
        id_name_list = []
        for category in data['res']:
            cid, cname = category['cid'], category['cname']
            if (cid, cname) not in seen:
                id_name_list.append({'id': cid, 'name': cname})
                seen.add((cid, cname))
            for item in category['data']:
                item_id, item_name = item['id'], item['name']
                if (item_id, item_name) not in seen:
                    id_name_list.append({'id': item_id, 'name': item_name})
                    seen.add((item_id, item_name))
        return id_name_list
    except RequestException as e:
        print(f"请求过程中发生错误: {e}")
        return []

def get_data_for_area(area_id, area_name, seen_ips, node_counter):
    url = (f'https://www.md40gf.info:20000/api/evmess?&proto=v2&code=H7XDMX&token=amSTaWVnkZWOk2xwb2lqapOfbGRplWiRYW2Yk5NqmWVjZJE=='
           f'&isvip=true&unlimit=true&area={area_id}')
    try:
        response = session.get(url, verify=False)
        response.raise_for_status()
        decrypted_data = decrypt_aes_cbc_nopadding(response.text, key, iv).decode('utf-8').strip()
        if decrypted_data.startswith("vmess://"):
            node = decode_vmess(decrypted_data)
            ip = node.get('add')
            if ip not in seen_ips:
                seen_ips.add(ip)
                node['ps'] = area_name
                encoded = 'vmess://' + base64.b64encode(json.dumps(node).encode('utf-8')).decode('utf-8')
                print(f'{COLOR_NEW}[{area_name}] 新节点信息:{COLOR_RESET}\n{encoded}\n')
                with open(output_file, "a", encoding='utf-8') as file:
                    file.write(encoded + '\n')
                node_counter += 1
            else:
                print(f'{COLOR_DUP}[{area_name}] 节点IP {ip} 已存在，跳过重复。{COLOR_RESET}')
    except HTTPError as http_err:
        print(f'{area_name}: 发生 HTTP 错误: {http_err}')
    except RequestException as req_err:
        print(f'{area_name}: 请求发生错误: {req_err}')
    except Exception as e:
        print(f'{area_name}: 发生未知错误: {e}')
    return node_counter

def main_loop(interval_seconds):
    node_counter = 0
    seen_ips = set()
    id_name_list = get_id_name_list()
    if not id_name_list:
        print("未获取到任何节点信息，程序退出。")
        return
    print(f"共获取到 {len(id_name_list)} 个区域/节点，开始获取详细数据...\n")
    while True:
        for item in id_name_list:
            node_counter = get_data_for_area(item['id'], item['name'], seen_ips, node_counter)
        print(f'\n已保存节点到 {output_file} 文件，共计 {node_counter} 个节点')
        print(f"等待 {interval_seconds} 秒后开始下一轮请求...\n")
        time.sleep(interval_seconds)

if __name__ == "__main__":
    try:
        interval = int(input("请输入请求间隔秒数（必须为正整数）："))
        if interval < 1:
            print("输入错误：间隔秒数必须大于0，程序退出。")
            exit(1)
    except ValueError:
        print("输入错误：请输入有效的整数，程序退出。")
        exit(1)
    main_loop(interval)
