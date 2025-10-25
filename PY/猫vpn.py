import requests
import uuid
import time
import random
import string
import os
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import yaml
import base64
import urllib.parse
from pathlib import Path

# 获取iPhone可用的Documents目录
docs_dir = str(Path.home() / "Documents")
nodes_file = os.path.join(docs_dir, "天猫VPN节点.TXT")
clash_file = os.path.join(docs_dir, "天猫VPN_clash.yaml")

# Function to generate random email
def generate_random_email():
    random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{random_string}@qq.com"

# Function to generate random User-Agent
def generate_random_user_agent():
    user_agents = [
        "okhttp/4.12.0",
        "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1"
    ]
    return random.choice(user_agents)

# Function to generate headers
def generate_headers(device_id, token=None, auth_token=None):
    headers = {
        "deviceid": device_id,
        "devicetype": "1",
        "Content-Type": "application/json; charset=UTF-8",
        "Host": "api.tianmiao.icu",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "User-Agent": generate_random_user_agent()
    }
    if token and auth_token:
        headers["token"] = token
        headers["authtoken"] = auth_token
    return headers

# Function to create a session with retry logic
def create_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    return session

# Function to sort nodes by region for display
def sort_nodes(nodes):
    region_order = ["HK-香港", "SG-新加坡", "JP-日本", "TW-台湾", "KR-韩国", "US-美国", "IDN-印尼", "MY-马来西亚"]
    sorted_nodes = []
    remaining_nodes = []
    
    for node in nodes:
        if "url" not in node:
            remaining_nodes.append(node)
            continue
            
        try:
            url_parts = node["url"].split("#")
            if len(url_parts) < 2:
                remaining_nodes.append(node)
                continue
                
            node_name = urllib.parse.unquote(url_parts[1])
            matched = False
            for region in region_order:
                if node_name.startswith(region):
                    sorted_nodes.append(node)
                    matched = True
                    break
            if not matched:
                remaining_nodes.append(node)
        except:
            remaining_nodes.append(node)
    
    return sorted_nodes + remaining_nodes

# Function to get node priority for sorting in proxy groups
def get_node_priority(node_name):
    priority_map = {
        "HK-香港": 1,
        "SG-新加坡": 2,
        "JP-日本": 3,
        "TW-台湾": 4,
        "KR-韩国": 5,
        "US-美国": 6
    }
    
    asian_regions = ["CN-中国", "TH-泰国", "VN-越南", "PH-菲律宾", "IN-印度", 
                     "IDN-印尼", "MY-马来西亚", "KH-柬埔寨", "LA-老挝", "MM-缅甸"]
    
    southeast_asian_regions = ["TH-泰国", "VN-越南", "PH-菲律宾", "ID-印尼", 
                              "MY-马来西亚", "KH-柬埔寨", "LA-老挝", "MM-缅甸", "SG-新加坡"]
    
    for region, priority in priority_map.items():
        if node_name.startswith(region):
            return priority
    
    for region in asian_regions:
        if node_name.startswith(region):
            return 7
    
    for region in southeast_asian_regions:
        if node_name.startswith(region) and not any(node_name.startswith(r) for r in priority_map.keys()):
            return 7
    
    return 8

# Function to save nodes to file
def save_nodes_to_file(nodes, file_path):
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            for node in nodes:
                if "url" not in node:
                    continue
                    
                try:
                    url_parts = node["url"].split("#")
                    if len(url_parts) < 2:
                        f.write(f"{node['url']}\n")
                    else:
                        decoded_name = urllib.parse.unquote(url_parts[1])
                        f.write(f"{url_parts[0]}#{decoded_name}\n")
                except:
                    f.write(f"{node['url']}\n")
        return file_path
    except IOError as e:
        print(f"保存节点到文件失败: {e}")
        return None

# Function to generate Clash config
def generate_clash_config(nodes, file_path):
    flag_emoji_map = {
        "HK-香港": "🇭🇰", "SG-新加坡": "🇸🇬", "JP-日本": "🇯🇵", "TW-台湾": "🇹🇼",
        "KR-韩国": "🇰🇷", "US-美国": "🇺🇸", "IDN-印尼": "🇮🇩", "MY-马来西亚": "🇲🇾",
        "CN-中国": "🇨🇳", "TH-泰国": "🇹🇭", "VN-越南": "🇻🇳", "PH-菲律宾": "🇵🇭",
        "IN-印度": "🇮🇳", "KH-柬埔寨": "🇰🇭", "LA-老挝": "🇱🇦", "MM-缅甸": "🇲🇲",
        "FR-法国": "🇫🇷", "TR-土耳其": "🇹🇷", "RU-俄罗斯": "🇷🇺", "MX-墨西哥": "🇲🇽",
        "AR-阿根廷": "🇦🇷", "UK-英国": "🇬🇧", "DXB-迪拜": "🇦🇪"
    }
    clash_config = {
        "dns": {
            "enable": True,
            "nameserver": ["119.29.29.29", "223.5.5.5"],
            "nameserver-policy": {
                "ChinaClassical,Apple,SteamCN,geosite:cn": ["tls://1.12.12.12", "223.5.5.5"]
            },
            "fallback": ["8.8.8.8", "1.1.1.1", "tls://dns.google:853", "tls://1.0.0.1:853"]
        },
        "proxies": [],
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": []},
            {"name": "🌍 国外媒体", "type": "select", "proxies": ["🚀 节点选择", "🎯 全球直连"]},
            {"name": "Ⓜ️ 微软服务", "type": "select", "proxies": ["🎯 全球直连", "🚀 节点选择"]},
            {"name": "🍎 苹果服务", "type": "select", "proxies": ["🎯 全球直连", "🚀 节点选择"]},
            {"name": "📦 PikPak", "type": "select", "proxies": ["🚀 节点选择", "🎯 全球直连"]},
            {"name": "🤖 OpenAI", "type": "select", "proxies": ["🚀 节点选择", "🎯 全球直连"]},
            {"name": "🐟 漏网之鱼", "type": "select", "proxies": ["🚀 节点选择", "🎯 全球直连"]},
            {"name": "🎯 全球直连", "type": "select", "proxies": ["DIRECT"]}
        ],
        "rules": [
            "IP-CIDR,129.146.160.80/32,DIRECT,no-resolve",
            "IP-CIDR,148.135.52.61/32,DIRECT,no-resolve",
            "IP-CIDR,148.135.56.101/32,DIRECT,no-resolve",
            "IP-CIDR,37.123.193.133/32,DIRECT,no-resolve",
            "IP-CIDR,111.119.203.69/32,DIRECT,no-resolve",
            "IP-CIDR,110.238.105.126/32,DIRECT,no-resolve",
            "IP-CIDR,166.108.206.148/32,DIRECT,no-resolve",
            "IP-CIDR,155.248.181.42/32,DIRECT,no-resolve",
            "IP-CIDR,176.126.114.184/32,DIRECT,no-resolve",
            "IP-CIDR,103.238.129.152/32,DIRECT,no-resolve",
            "IP-CIDR,45.66.217.124/32,DIRECT,no-resolve",
            "IP-CIDR,183.2.133.144/32,DIRECT,no-resolve",
            "IP-CIDR,103.103.245.13/32,DIRECT,no-resolve",
            "DOMAIN,oiyun.de,DIRECT",
            "DOMAIN,github.moeyy.xyz,DIRECT",
            "DOMAIN,hk.xybhdy.top,DIRECT",
            "DOMAIN,hd1dc.com,DIRECT",
            "RULE-SET,LocalAreaNetwork,DIRECT",
            "RULE-SET,BanAD,REJECT",
            "RULE-SET,BanAdobe,REJECT",
            "RULE-SET,GoogleFCM,🚀 节点选择",
            "RULE-SET,SteamCN,DIRECT",
            "RULE-SET,Microsoft,Ⓜ️ 微软服务",
            "RULE-SET,Apple,🍎 苹果服务",
            "RULE-SET,Telegram,🚀 节点选择",
            "RULE-SET,PikPak,📦 PikPak",
            "RULE-SET,OpenAI,🤖 OpenAI",
            "RULE-SET,Claude,🤖 OpenAI",
            "RULE-SET,Gemini,🤖 OpenAI",
            "RULE-SET,ProxyMedia,🌍 国外媒体",
            "RULE-SET,ProxyClassical,🚀 节点选择",
            "RULE-SET,ChinaCIDr,DIRECT",
            "RULE-SET,ChinaClassical,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,🐟 漏网之鱼"
        ],
        "rule-providers": {
            "Apple": {"behavior": "classical", "interval": 604800, "path": "./rules/Apple.yaml", "type": "http", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Apple/Apple.yaml"},
            "BanAD": {"behavior": "domain", "interval": 604800, "path": "./rules/BanAD.yaml", "type": "http", "url": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt"},
            "BanAdobe": {"behavior": "classical", "interval": 604800, "path": "./rules/BanAdobe.yaml", "type": "http", "url": "https://raw.githubusercontent.com/ignaciocastro/a-dove-is-dumb/main/clash.yaml"},
            "ChinaCIDr": {"behavior": "ipcidr", "interval": 604800, "path": "./rules/CNCIDR.yaml", "type": "http", "url": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/cncidr.txt"},
            "ChinaClassical": {"behavior": "domain", "interval": 604800, "path": "./rules/ChinaClassical.yaml", "type": "http", "url": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt"},
            "Claude": {"behavior": "classical", "interval": 604800, "path": "./rules/Claude.yaml", "type": "http", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Claude/Claude.yaml"},
            "Gemini": {"behavior": "classical", "interval": 604800, "path": "./rules/Gemini.yaml", "type": "http", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Gemini/Gemini.yaml"},
            "GoogleFCM": {"behavior": "classical", "interval": 604800, "path": "./rules/GoogleFCM.yaml", "type": "http", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/GoogleFCM/GoogleFCM.yaml"},
            "LocalAreaNetwork": {"behavior": "classical", "interval": 604800, "path": "./rules/LocalAreaNetwork.yaml", "type": "http", "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/LocalAreaNetwork.yaml"},
            "Microsoft": {"behavior": "classical", "interval": 604800, "path": "./rules/Microsoft.yaml", "type": "http", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Microsoft/Microsoft.yaml"},
            "OpenAI": {"behavior": "classical", "interval": 604800, "path": "./rules/OpenAI.yaml", "type": "http", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.yaml"},
            "PikPak": {"behavior": "classical", "interval": 604800, "path": "./rules/PikPak.yaml", "type": "http", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/PikPak/PikPak.yaml"},
            "ProxyClassical": {"behavior": "domain", "interval": 604800, "path": "./rules/ProxyClassical.yaml", "type": "http", "url": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt"},
            "ProxyMedia": {"behavior": "classical", "interval": 604800, "path": "./rules/ProxyMedia.yaml", "type": "http", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/GlobalMedia/GlobalMedia_Classical.yaml"},
            "SteamCN": {"behavior": "classical", "interval": 604800, "path": "./rules/SteamCN.yaml", "type": "http", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/SteamCN/SteamCN.yaml"},
            "Telegram": {"behavior": "classical", "interval": 604800, "path": "./rules/Telegram.yaml", "type": "http", "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Telegram.yaml"}
        }
    }
    
    node_info_list = []
    
    for node in nodes:
        if "url" not in node:
            continue
            
        try:
            url = node["url"]
            if "#" not in url:
                continue
                
            url_parts = url.split("#")
            if len(url_parts) < 2:
                continue
                
            name = urllib.parse.unquote(url_parts[1])
            
            flag_added = False
            for region, emoji in flag_emoji_map.items():
                if name.startswith(region):
                    name = f"{emoji}{name}"
                    flag_added = True
                    break
            if not flag_added:
                name = f"🌐{name}"
            
            if "@" not in url_parts[0]:
                continue
                
            auth_part, server_port = url_parts[0].split("@")
            if "://" not in auth_part:
                continue
                
            base64_auth = auth_part.split("://")[1]
            cipher_password = base64.b64decode(base64_auth + "==").decode("utf-8")
            
            if ":" not in cipher_password:
                continue
                
            cipher, password = cipher_password.split(":", 1)
            
            server_port_parts = server_port.split(":")
            if len(server_port_parts) < 2:
                continue
                
            server = server_port_parts[0]
            port = server_port_parts[1].split("/")[0] if "/" in server_port_parts[1] else server_port_parts[1]
            
            proxy = {
                "name": name,
                "type": "ss",
                "server": server,
                "port": int(port),
                "cipher": cipher,
                "password": password,
                "udp": True
            }
            
            priority = get_node_priority(urllib.parse.unquote(url_parts[1]))
            node_info_list.append({
                "proxy": proxy,
                "priority": priority,
                "name": name
            })
            
        except Exception as e:
            print(f"解析节点 {node.get('url', '未知')} 失败: {e}")
            continue
    
    node_info_list.sort(key=lambda x: (x["priority"], x["name"]))
    
    for node_info in node_info_list:
        clash_config["proxies"].append(node_info["proxy"])
        clash_config["proxy-groups"][0]["proxies"].append(node_info["name"])
    
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
        return file_path
    except IOError as e:
        print(f"保存Clash配置文件失败: {e}")
        return None

# Main function
def main():
    device_id = str(uuid.uuid4())
    email = generate_random_email()
    password = "asd789369"
    invite_code = "ghqhsqRD"
    session = create_session()

    print("注册中……")
    register_url = "https://api.tianmiao.icu/api/register"
    register_data = {
        "email": email,
        "invite_code": "",
        "password": password,
        "password_word": password
    }
    headers = generate_headers(device_id)
    
    try:
        response = session.post(register_url, headers=headers, json=register_data, verify=True, timeout=10)
        response.raise_for_status()
        result = response.json()
        
        if result.get("code") != 1:
            print(f"注册失败: {result.get('message')}")
            return
        
        token = result["data"]["auth_data"]
        auth_token = result["data"]["token"]
        print(f"注册成功: 邮箱 {email}")
        
    except requests.exceptions.SSLError:
        print("注册中遇到SSL错误，尝试禁用SSL验证……")
        try:
            response = session.post(register_url, headers=headers, json=register_data, verify=False, timeout=10)
            response.raise_for_status()
            result = response.json()
            
            if result.get("code") != 1:
                print(f"注册失败: {result.get('message')}")
                return
                
            token = result["data"]["auth_data"]
            auth_token = result["data"]["token"]
            print(f"注册成功: 邮箱 {email}")
            
        except requests.RequestException as e:
            print(f"注册失败: {e}")
            return
    except requests.RequestException as e:
        print(f"注册失败: {e}")
        return
    
    time.sleep(random.uniform(2, 5))

    print("绑定邀请码中……")
    bind_url = "https://api.tianmiao.icu/api/bandInviteCode"
    bind_data = {"invite_code": invite_code}
    headers = generate_headers(device_id, token, auth_token)
    
    try:
        response = session.post(bind_url, headers=headers, json=bind_data, verify=True, timeout=10)
        response.raise_for_status()
        result = response.json()
        
        if result.get("code") != 1:
            print(f"邀请码绑定失败: {result.get('message')}")
            return
        
        print(f"邀请码绑定成功: {invite_code}")
        
    except requests.exceptions.SSLError:
        print("绑定邀请码遇到SSL错误，尝试禁用SSL验证……")
        try:
            response = session.post(bind_url, headers=headers, json=bind_data, verify=False, timeout=10)
            response.raise_for_status()
            result = response.json()
            
            if result.get("code") != 1:
                print(f"邀请码绑定失败: {result.get('message')}")
                return
                
            print(f"邀请码绑定成功: {invite_code}")
        except requests.RequestException as e:
            print(f"邀请码绑定失败: {e}")
            return
    except requests.RequestException as e:
        print(f"邀请码绑定失败: {e}")
        return
    
    time.sleep(random.uniform(2, 5))

    print("获取节点列表中……")
    node_url = "https://api.tianmiao.icu/api/nodeListV2"
    node_data = {
        "protocol": "all",
        "include_ss": "1",
        "include_shadowsocks": "1",
        "include_trojan": "1"
    }
    
    try:
        response = session.post(node_url, headers=headers, json=node_data, verify=True, timeout=10)
        response.raise_for_status()
        result = response.json()
        
        if result.get("code") != 1:
            print(f"节点列表获取失败: {result.get('message')}")
            return
        
        print("节点列表获取成功")
        
        vip_nodes = []
        for node_group in result["data"]:
            if node_group["type"] == "vip" and "node" in node_group:
                for node in node_group["node"]:
                    if isinstance(node, dict) and "url" in node:
                        vip_nodes.append(node)
        
        print(f"找到 {len(vip_nodes)} 个VIP节点")
        
        if vip_nodes:
            sorted_nodes = sort_nodes(vip_nodes)
            
            print("\n前5个付费节点:")
            for node in sorted_nodes[:5]:
                if "url" in node:
                    url_parts = node["url"].split("#")
                    if len(url_parts) > 1:
                        decoded_name = urllib.parse.unquote(url_parts[1])
                        print(f"{url_parts[0]}#{decoded_name}")
                    else:
                        print(node["url"])
            
            nodes_file_path = save_nodes_to_file(sorted_nodes, nodes_file)
            if nodes_file_path:
                print(f"\n节点已保存至: {nodes_file_path}")
            
            clash_file_path = generate_clash_config(sorted_nodes, clash_file)
            if clash_file_path:
                print(f"Clash配置文件已保存至: {clash_file_path}")
        else:
            print("没有找到VIP节点")
        
    except requests.exceptions.SSLError:
        print("获取节点列表遇到SSL错误，尝试禁用SSL验证……")
        try:
            response = session.post(node_url, headers=headers, json=node_data, verify=False, timeout=10)
            response.raise_for_status()
            result = response.json()
            
            if result.get("code") != 1:
                print(f"节点列表获取失败: {result.get('message')}")
                return
                
            print("节点列表获取成功")
            
            vip_nodes = []
            for node_group in result["data"]:
                if node_group["type"] == "vip" and "node" in node_group:
                    for node in node_group["node"]:
                        if isinstance(node, dict) and "url" in node:
                            vip_nodes.append(node)
            
            print(f"找到 {len(vip_nodes)} 个VIP节点")
            
            if vip_nodes:
                sorted_nodes = sort_nodes(vip_nodes)
                
                print("\n前5个付费节点:")
                for node in sorted_nodes[:5]:
                    if "url" in node:
                        url_parts = node["url"].split("#")
                        if len(url_parts) > 1:
                            decoded_name = urllib.parse.unquote(url_parts[1])
                            print(f"{url_parts[0]}#{decoded_name}")
                        else:
                            print(node["url"])
                
                nodes_file_path = save_nodes_to_file(sorted_nodes, nodes_file)
                if nodes_file_path:
                    print(f"\n节点已保存至: {nodes_file_path}")
                
                clash_file_path = generate_clash_config(sorted_nodes, clash_file)
                if clash_file_path:
                    print(f"Clash配置文件已保存至: {clash_file_path}")
            else:
                print("没有找到VIP节点")
                
        except requests.RequestException as e:
            print(f"节点列表获取失败: {e}")
            return
    except requests.RequestException as e:
        print(f"节点列表获取失败: {e}")
        return
    except Exception as e:
        print(f"处理节点数据时发生错误: {e}")
        return

if __name__ == "__main__":
    main()
