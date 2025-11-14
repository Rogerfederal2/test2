#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
综合节点采集器
整合多个可用脚本，采集所有节点信息并生成 base64 和 Clash 配置文件
"""

import requests
import base64
import json
import yaml
import re
import uuid
import time
import random
import string
from Crypto.Cipher import AES
from urllib.parse import urlparse, parse_qs, unquote, quote
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import os
from datetime import datetime

# ==================== 配置 ====================
# 获取脚本所在目录的父目录（项目根目录）
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
OUTPUT_DIR = PROJECT_ROOT
BASE64_FILE = os.path.join(OUTPUT_DIR, "nodes_base64.txt")
CLASH_FILE = os.path.join(OUTPUT_DIR, "clash.yaml")
NODES_FILE = os.path.join(OUTPUT_DIR, "nodes.txt")

# 确保输出目录存在
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ==================== 工具函数 ====================

def create_session():
    """创建带重试的会话"""
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.mount("http://", HTTPAdapter(max_retries=retries))
    return session

# ==================== 1. VMess 节点采集 (来自 VMesslinks-main) ====================

def get_vmess_nodes():
    """从 VMesslinks API 获取 VMess 节点"""
    print("📡 正在采集 VMess 节点...")
    nodes = set()
    url = "https://www.m4twf.xyz:20000/api/evmess?&proto=v2&platform=android&googleplay=1&ver=3.0.5&deviceid=1bcec3395995cf19unknown&unicode=1bcec3395995cf19unknown&t=1717462751804&code=9GFZ2R&recomm_code=&f=2024-06-04&install=2024-06-04&token=amSTaWVnkZWOk2xscWlsb5mZbmRolGuRZ2mQl5Jrkmhnaw==&package=com.honeybee.network&area="
    key = b'ks9KUrbWJj46AftX'
    iv = b'ks9KUrbWJj46AftX'
    
    try:
        for i in range(20):  # 减少请求次数
            try:
                response = requests.get(url + str(random.randint(1, 100)), timeout=10)
                if response.status_code == 200:
                    encrypted_data = response.text.strip()
                    encrypted_data_bytes = base64.b64decode(encrypted_data)
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    decrypted_data = cipher.decrypt(encrypted_data_bytes)
                    node_info = decrypted_data.decode('utf-8', errors='ignore').rstrip('\x00')
                    if node_info.startswith('vmess://'):
                        nodes.add(node_info)
            except Exception as e:
                continue
        print(f"  ✅ 采集到 {len(nodes)} 个 VMess 节点")
    except Exception as e:
        print(f"  ❌ VMess 节点采集失败: {e}")
    
    return list(nodes)

# ==================== 2. SuperVPN 节点采集 (Trojan) ====================

def get_supervpn_nodes():
    """从 SuperVPN API 获取 Trojan 节点"""
    print("📡 正在采集 SuperVPN (Trojan) 节点...")
    nodes = []
    uid = "3690911436885991424"
    
    try:
        import pyaes
        api_url = "https://api.9527.click/v2/node/list"
        headers = {
            'Host': 'api.9527.click',
            'Content-Type': 'application/json',
            'Connection': 'keep-alive',
            'Accept': '*/*',
            'User-Agent': 'International/3.3.35 (iPhone; iOS 18.0.1; Scale/3.00)',
            'Accept-Language': 'zh-Hans-CN;q=1',
            'Accept-Encoding': 'gzip, deflate, br'
        }
        payload = {
            "key": "G8Jxb2YtcONGmQwN7b5odg==",
            "uid": uid,
            "vercode": "1",
            "uuid": str(uuid.uuid4())
        }
        
        response = requests.post(api_url, headers=headers, json=payload, timeout=15)
        if response.status_code == 200:
            node_data = response.json()
            if 'data' in node_data:
                encrypted_key = b'VXH2THdPBsHEp+TY'
                encrypted_iv = b'VXH2THdPBsHEp+TY'
                
                for node in node_data['data']:
                    try:
                        # 解密 IP/Host
                        if 'ip' in node and node['ip']:
                            decrypted_data = base64.b64decode(node['ip'])
                            aes = pyaes.AESModeOfOperationCBC(encrypted_key, iv=encrypted_iv)
                            decrypted_output = b""
                            data = decrypted_data
                            while data:
                                decrypted_output += aes.decrypt(data[:16])
                                data = data[16:]
                            padding_length = decrypted_output[-1]
                            node['ip'] = decrypted_output[:-padding_length].decode('utf-8')
                        
                        if 'host' in node and node['host']:
                            decrypted_data = base64.b64decode(node['host'])
                            aes = pyaes.AESModeOfOperationCBC(encrypted_key, iv=encrypted_iv)
                            decrypted_output = b""
                            data = decrypted_data
                            while data:
                                decrypted_output += aes.decrypt(data[:16])
                                data = data[16:]
                            padding_length = decrypted_output[-1]
                            node['host'] = decrypted_output[:-padding_length].decode('utf-8')
                        
                        host = node.get('host') or node.get('ip')
                        name = node.get('name', 'Unknown')
                        if host:
                            link = f"trojan://{uid}@{host}:443#{name}"
                            nodes.append(link)
                    except Exception:
                        continue
        print(f"  ✅ 采集到 {len(nodes)} 个 Trojan 节点")
    except ImportError:
        print("  ⚠️  缺少 pyaes 库，跳过 SuperVPN 节点采集")
    except Exception as e:
        print(f"  ❌ SuperVPN 节点采集失败: {e}")
    
    return nodes

# ==================== 3. 天猫VPN 节点采集 (SS) ====================

def get_tianmiao_nodes():
    """从天猫VPN API 获取 SS 节点"""
    print("📡 正在采集天猫VPN (SS) 节点...")
    nodes = []
    
    try:
        device_id = str(uuid.uuid4())
        email = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)) + "@qq.com"
        password = "asd789369"
        invite_code = "ghqhsqRD"
        session = create_session()
        
        # 注册
        register_url = "https://api.tianmiao.icu/api/register"
        register_data = {
            "email": email,
            "invite_code": "",
            "password": password,
            "password_word": password
        }
        headers = {
            "deviceid": device_id,
            "devicetype": "1",
            "Content-Type": "application/json; charset=UTF-8",
            "Host": "api.tianmiao.icu",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "User-Agent": "okhttp/4.12.0"
        }
        
        response = session.post(register_url, headers=headers, json=register_data, verify=False, timeout=10)
        if response.status_code == 200:
            result = response.json()
            if result.get("code") == 1:
                token = result["data"]["auth_data"]
                auth_token = result["data"]["token"]
                headers["token"] = token
                headers["authtoken"] = auth_token
                
                time.sleep(2)
                
                # 绑定邀请码
                bind_url = "https://api.tianmiao.icu/api/bandInviteCode"
                session.post(bind_url, headers=headers, json={"invite_code": invite_code}, verify=False, timeout=10)
                
                time.sleep(2)
                
                # 获取节点列表
                node_url = "https://api.tianmiao.icu/api/nodeListV2"
                node_data = {
                    "protocol": "all",
                    "include_ss": "1",
                    "include_shadowsocks": "1",
                    "include_trojan": "1"
                }
                
                response = session.post(node_url, headers=headers, json=node_data, verify=False, timeout=10)
                if response.status_code == 200:
                    result = response.json()
                    if result.get("code") == 1:
                        for node_group in result["data"]:
                            if node_group["type"] == "vip" and "node" in node_group:
                                for node in node_group["node"]:
                                    if isinstance(node, dict) and "url" in node:
                                        nodes.append(node["url"])
        
        print(f"  ✅ 采集到 {len(nodes)} 个天猫VPN节点")
    except Exception as e:
        print(f"  ❌ 天猫VPN节点采集失败: {e}")
    
    return nodes

# ==================== 4. PIA 节点采集 (SS) ====================

def get_pia_nodes():
    """从 PIA 获取 SS 节点"""
    print("📡 正在采集 PIA (SS) 节点...")
    nodes = set()
    
    try:
        url1 = "https://raw.githubusercontent.com/DemanNL/PIA-shadowsocks-android-guide/main/profiles.json"
        url2 = "https://raw.githubusercontent.com/Minecraftpe2007/joshua/master/piavpn.json"
        url3 = "https://serverlist.piaservers.net/shadow_socks"
        
        # 获取 JSON 数据
        for url in [url1, url2]:
            try:
                response = requests.get(url, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    for item in data:
                        base64_info = f"{item['method']}:{item['password']}@{item['server']}:{item['server_port']}"
                        base64_encoded = base64.b64encode(base64_info.encode('utf-8')).decode('utf-8')
                        ss_url = f"ss://{base64_encoded}#{item['remarks']}"
                        nodes.add(ss_url)
            except Exception:
                continue
        
        # 获取 serverlist 数据
        try:
            response = requests.get(url3, timeout=15)
            if response.status_code == 200:
                raw_data = response.text
                json_data = raw_data.split(']')[0] + ']'
                data = json.loads(json_data)
                for item in data:
                    cipher_key = f"{item['cipher']}:{item['key']}"
                    encoded_cipher_key = base64.b64encode(cipher_key.encode()).decode()
                    ss_link = f"ss://{encoded_cipher_key}@{item['host']}:{item['port']}#{item['region']}"
                    nodes.add(ss_link)
        except Exception:
            pass
        
        print(f"  ✅ 采集到 {len(nodes)} 个 PIA 节点")
    except Exception as e:
        print(f"  ❌ PIA 节点采集失败: {e}")
    
    return list(nodes)

# ==================== 5. MarketingInMyHouse 节点采集 (SSR) ====================

def get_marketinginmyhouse_nodes():
    """从 marketinginmyhouse.com API 获取 SSR 节点"""
    print("📡 正在采集 MarketingInMyHouse (SSR) 节点...")
    nodes = []
    
    try:
        url = 'https://marketinginmyhouse.com/api/servers?isPremium=1'
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            servers = data.get('servers', [])
            
            for server in servers:
                try:
                    # 提取服务器信息
                    ip = server.get('ip', '')
                    port = server.get('port', '')
                    password = server.get('password', '')
                    title = server.get('title', '')
                    
                    if not ip or not port or not password:
                        continue
                    
                    # SSR 链接格式: 服务器:端口:协议:加密:混淆:base64(密码)/?remarks=base64(备注)&protoparam=&obfsparam=
                    # 协议: origin
                    # 加密: aes-256-cfb
                    # 混淆: plain
                    
                    # 对密码进行 base64 编码
                    password_b64 = base64.b64encode(password.encode('utf-8')).decode('utf-8')
                    
                    # 对备注进行 base64 编码
                    remarks_b64 = base64.b64encode(title.encode('utf-8')).decode('utf-8')
                    
                    # 构建 SSR 链接的主部分
                    ssr_main = f"{ip}:{port}:origin:aes-256-cfb:plain:{password_b64}"
                    
                    # 构建参数部分
                    params = f"remarks={remarks_b64}&protoparam=&obfsparam="
                    
                    # 组合完整链接
                    ssr_full = f"{ssr_main}/?{params}"
                    
                    # 对整个链接进行 base64 编码
                    ssr_encoded = base64.b64encode(ssr_full.encode('utf-8')).decode('utf-8')
                    
                    # 生成最终的 SSR 链接
                    ssr_link = f"ssr://{ssr_encoded}"
                    
                    nodes.append(ssr_link)
                    
                except Exception as e:
                    continue
            
            print(f"  ✅ 采集到 {len(nodes)} 个 MarketingInMyHouse 节点")
        else:
            print(f"  ❌ API 请求失败，状态码: {response.status_code}")
            
    except Exception as e:
        print(f"  ❌ MarketingInMyHouse 节点采集失败: {e}")
    
    return nodes

# ==================== 6. 派大星节点采集 (SS) ====================

def get_paidaxing_nodes():
    """从派大星 API 获取 SS 节点"""
    print("📡 正在采集派大星 (SS) 节点...")
    nodes = []
    
    try:
        import pyaes
        import binascii
        
        url = 'https://ioa.onskrgames.uk/getLines'
        headers = {
            'accept': '/',
            'accept-language': 'zh-Hans-CN;q=1, en-CN;q=0.9',
            'appversion': '1.3.1',
            'user-agent': 'SkrKK/1.3.1 (iPhone; iOS 13.5; Scale/2.00)',
            'content-type': 'application/x-www-form-urlencoded',
            'Cookie': 'PHPSESSID=fnffo1ivhvt0ouo6ebqn86a0d4'
        }
        
        d = b'65151f8d966bf596'
        e = b'88ca0f0ea1ecf975'
        
        def decrypt(g, d, e):
            h = pyaes.AESModeOfOperationCBC(d, iv=e)
            i = b''.join(h.decrypt(g[j:j+16]) for j in range(0, len(g), 16))
            return i[:-i[-1]]
        
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            encrypted_hex = response.text.strip()
            encrypted_bytes = binascii.unhexlify(encrypted_hex)
            decrypted = decrypt(encrypted_bytes, d, e)
            data = json.loads(decrypted)
            
            if 'data' in data and isinstance(data['data'], list):
                for o in data['data']:
                    p = f"aes-256-cfb:{o['password']}@{o['ip']}:{o['port']}"
                    q = base64.b64encode(p.encode('utf-8')).decode('utf-8')
                    r = f"ss://{q}#{o['title']}"
                    nodes.append(r)
        
        print(f"  ✅ 采集到 {len(nodes)} 个派大星节点")
    except ImportError:
        print("  ⚠️  缺少 pyaes 库，跳过派大星节点采集")
    except Exception as e:
        print(f"  ❌ 派大星节点采集失败: {e}")
    
    return nodes

# ==================== 6. 从订阅链接获取节点 ====================

def get_nodes_from_subscription(url):
    """从订阅链接获取节点"""
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            content = response.text.strip()
            # 尝试 base64 解码
            try:
                decoded = base64.b64decode(content + '===').decode('utf-8', errors='ignore')
                content = decoded
            except:
                pass
            # 提取节点链接
            nodes = re.findall(r'(?:vmess|vless|ss|trojan|ssr)://[^\s]+', content, re.MULTILINE)
            return nodes
    except Exception:
        pass
    return []

def get_subscription_nodes():
    """从多个订阅链接获取节点"""
    print("📡 正在从订阅链接采集节点...")
    all_nodes = []
    
    subscription_urls = [
        "https://raw.githubusercontent.com/moneyfly1/highnodes/refs/heads/main/data/v2ray.txt",
        "https://raw.githubusercontent.com/jianguogongyong/ssr_subscrible_tool/refs/heads/master/node.txt",
        "https://raw.githubusercontent.com/jgchengxin/ssr_subscrible_tool/refs/heads/master/node.txt",
    ]
    
    for url in subscription_urls:
        try:
            nodes = get_nodes_from_subscription(url)
            all_nodes.extend(nodes)
        except Exception:
            continue
    
    print(f"  ✅ 从订阅链接采集到 {len(all_nodes)} 个节点")
    return all_nodes

# ==================== 节点去重和格式化 ====================

def deduplicate_nodes(nodes):
    """节点去重"""
    seen = set()
    unique_nodes = []
    for node in nodes:
        if node and node not in seen:
            seen.add(node)
            unique_nodes.append(node)
    return unique_nodes

# ==================== 生成 Clash 配置 ====================

def parse_node_to_clash(node_url):
    """将节点 URL 解析为 Clash 配置"""
    try:
        if node_url.startswith('vmess://'):
            config_part = node_url.split('://')[1].split('#')[0]
            padding = len(config_part) % 4
            if padding:
                config_part += '=' * (4 - padding)
            vmess_config = json.loads(base64.b64decode(config_part).decode('utf-8', errors='ignore'))
            
            name = unquote(node_url.split('#')[1]) if '#' in node_url else vmess_config.get('ps', 'VMess')
            
            proxy = {
                'name': name,
                'type': 'vmess',
                'server': vmess_config.get('add', ''),
                'port': int(vmess_config.get('port', 0)),
                'uuid': vmess_config.get('id', ''),
                'alterId': int(vmess_config.get('aid', 0)),
                'cipher': vmess_config.get('scy', 'auto'),
                'udp': True,
                'tls': str(vmess_config.get('tls', '')).lower() == 'tls',
                'skip-cert-verify': True
            }
            
            if 'net' in vmess_config:
                proxy['network'] = vmess_config['net']
                if vmess_config['net'] == 'ws':
                    proxy['ws-opts'] = {
                        'path': vmess_config.get('path', '/'),
                        'headers': {'Host': vmess_config.get('host', proxy['server'])}
                    }
            
            if proxy.get('tls'):
                proxy['servername'] = vmess_config.get('host', proxy['server'])
            
            return proxy
            
        elif node_url.startswith('trojan://'):
            parsed = urlparse(node_url)
            query = parse_qs(parsed.query)
            name = unquote(parsed.fragment) if parsed.fragment else 'Trojan'
            
            return {
                'name': name,
                'type': 'trojan',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'password': parsed.username,
                'udp': True,
                'sni': query.get('sni', [parsed.hostname])[0] if query.get('sni') else parsed.hostname,
                'skip-cert-verify': True
            }
            
        elif node_url.startswith('ss://'):
            parsed = urlparse(node_url)
            name = unquote(parsed.fragment) if parsed.fragment else 'SS'
            
            user_info_b64 = parsed.username
            padding = len(user_info_b64) % 4
            if padding:
                user_info_b64 += '=' * (4 - padding)
            
            try:
                decoded_user_info = base64.urlsafe_b64decode(user_info_b64).decode('utf-8')
                cipher, password = decoded_user_info.split(':', 1)
            except:
                return None
            
            return {
                'name': name,
                'type': 'ss',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'cipher': cipher,
                'password': password,
                'udp': True
            }
            
        elif node_url.startswith('vless://'):
            parsed = urlparse(node_url)
            query = parse_qs(parsed.query)
            name = unquote(parsed.fragment) if parsed.fragment else 'VLESS'
            
            return {
                'name': name,
                'type': 'vless',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'uuid': parsed.username,
                'tls': query.get('security', ['none'])[0] == 'tls',
                'skip-cert-verify': True
            }
    except Exception as e:
        return None
    
    return None

def generate_clash_config(nodes):
    """生成 Clash 配置文件"""
    print("📝 正在生成 Clash 配置...")
    
    clash_config = {
        'dns': {
            'enable': True,
            'nameserver': ['119.29.29.29', '223.5.5.5'],
            'fallback': ['8.8.8.8', '1.1.1.1']
        },
        'proxies': [],
        'proxy-groups': [
            {'name': '🚀 节点选择', 'type': 'select', 'proxies': []},
            {'name': '🎯 全球直连', 'type': 'select', 'proxies': ['DIRECT']}
        ],
        'rules': [
            'GEOIP,CN,DIRECT',
            'MATCH,🚀 节点选择'
        ]
    }
    
    proxy_names = []
    for node_url in nodes:
        proxy = parse_node_to_clash(node_url)
        if proxy:
            clash_config['proxies'].append(proxy)
            proxy_names.append(proxy['name'])
    
    clash_config['proxy-groups'][0]['proxies'] = proxy_names
    
    return clash_config

# ==================== 主函数 ====================

def main():
    print("="*60)
    print("🚀 综合节点采集器")
    print("="*60)
    print(f"开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    all_nodes = []
    
    # 采集各个源的节点
    all_nodes.extend(get_vmess_nodes())
    all_nodes.extend(get_supervpn_nodes())
    all_nodes.extend(get_tianmiao_nodes())
    all_nodes.extend(get_pia_nodes())
    all_nodes.extend(get_paidaxing_nodes())
    all_nodes.extend(get_marketinginmyhouse_nodes())
    all_nodes.extend(get_subscription_nodes())
    
    # 去重
    print(f"\n📊 去重前节点数量: {len(all_nodes)}")
    unique_nodes = deduplicate_nodes(all_nodes)
    print(f"📊 去重后节点数量: {len(unique_nodes)}")
    
    if not unique_nodes:
        print("\n❌ 未采集到任何节点，程序退出")
        return
    
    # 保存原始节点文件
    print(f"\n💾 正在保存节点文件...")
    with open(NODES_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(unique_nodes))
    print(f"  ✅ 节点已保存到: {NODES_FILE}")
    
    # 生成 Base64 文件
    print(f"\n💾 正在生成 Base64 文件...")
    nodes_content = '\n'.join(unique_nodes)
    base64_content = base64.b64encode(nodes_content.encode('utf-8')).decode('utf-8')
    with open(BASE64_FILE, 'w', encoding='utf-8') as f:
        f.write(base64_content)
    print(f"  ✅ Base64 文件已保存到: {BASE64_FILE}")
    
    # 生成 Clash 配置
    clash_config = generate_clash_config(unique_nodes)
    with open(CLASH_FILE, 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    print(f"  ✅ Clash 配置文件已保存到: {CLASH_FILE}")
    print(f"  📊 Clash 配置包含 {len(clash_config['proxies'])} 个代理节点")
    
    print("\n" + "="*60)
    print("✅ 节点采集完成！")
    print(f"结束时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    print(f"\n📁 输出文件:")
    print(f"  - 原始节点: {NODES_FILE}")
    print(f"  - Base64编码: {BASE64_FILE}")
    print(f"  - Clash配置: {CLASH_FILE}")

if __name__ == "__main__":
    main()

