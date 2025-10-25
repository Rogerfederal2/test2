import re
import requests
import base64
import urllib3
from urllib.parse import unquote, urlparse, parse_qs, quote
import yaml
import sys
import json
import os

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# iOS 沙盒路径
DOCUMENTS_PATH = os.path.join(os.path.expanduser("~"), "Documents")
os.makedirs(DOCUMENTS_PATH, exist_ok=True)

GENERATED_CLASH_CONFIG_PATH = os.path.join(DOCUMENTS_PATH, "负载均衡.yaml")
DEBUG_LOG_PATH = os.path.join(DOCUMENTS_PATH, "debug_nodes.txt")

BROWSER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

class NetcutSubscription:
    def __init__(self):
        self.session = requests.Session()
        self.base_headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 15; RMX5062 Build/UKQ1.231108.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.7258.144 Mobile Safari/537.36",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7"
        }
    
    def get_note_info(self, note_name, note_pwd=None):
        print("⏳ 信息获取中……")
        sys.stdout.flush()
        url = "https://api.txttool.cn/netcut/note/info/"
        headers = {
            "Host": "api.txttool.cn",
            "Connection": "keep-alive",
            "sec-ch-ua-platform": "\"Android\"",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "sec-ch-ua": "\"Not;A=Brand\";v=\"99\", \"Android WebView\";v=\"139\", \"Chromium\";v=\"139\"",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "sec-ch-ua-mobile": "?1",
            "Origin": "https://netcut.cn",
            "X-Requested-With": "com.mmbox.xbrowser",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://netcut.cn/",
        }
        headers.update(self.base_headers)
        
        data = f"note_name={quote(note_name)}"
        if note_pwd:
            data += f"&note_pwd={quote(note_pwd)}"
        
        try:
            response = self.session.post(url, headers=headers, data=data)
            if response.status_code == 200:
                note_data = response.json()
                if note_data.get('status') == 1 and 'note_content' in note_data.get('data', {}):
                    return self.extract_subscription_links(note_data['data']['note_content'])
            print("❌ 信息获取失败")
            sys.stdout.flush()
            return []
        except Exception as e:
            print(f"❌ 信息获取失败: {e}")
            sys.stdout.flush()
            return []
    
    def extract_subscription_links(self, content):
        lines = content.strip().split('\n')
        valid_links = []
        for line in lines:
            line = line.strip()
            if (line.startswith('http://') or line.startswith('https://') or 
                line.startswith('vless://') or line.startswith('vmess://') or
                line.startswith('trojan://') or line.startswith('ss://') or
                line.startswith('subscribe://')):
                valid_links.append(line)
        return valid_links

class NodeProcessor:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.name_simplification_printed = False

    def parse_subscribe_url(self, subscribe_url):
        print("📜 信息处理中……")
        sys.stdout.flush()
        try:
            headers = {'User-Agent': BROWSER_USER_AGENT}
            response = self.session.get(subscribe_url, timeout=15, headers=headers)
            response.raise_for_status()
            content = response.text
            try:
                decoded_content = base64.b64decode(content + '===').decode('utf-8', errors='ignore')
            except:
                decoded_content = content
            try:
                decoded_content = base64.urlsafe_b64decode(content + '===').decode('utf-8', errors='ignore')
            except:
                pass
            nodes = re.findall(r'(?:vmess|vless|ss|trojan)://[^\s]+', decoded_content, re.MULTILINE)
            return nodes
        except Exception as e:
            print(f"❌ 解析订阅链接失败: {e}")
            sys.stdout.flush()
            return []

    def get_node_name(self, node_url):
        if not self.name_simplification_printed:
            print("🔄 信息简化中……")
            self.name_simplification_printed = True
            sys.stdout.flush()
        try:
            if node_url.startswith('vmess://'):
                config_part = node_url.split('://')[1].split('#')[0]
                padding = len(config_part) % 4
                if padding:
                    config_part += '=' * (4 - padding)
                vmess_config = json.loads(base64.b64decode(config_part).decode('utf-8', errors='ignore'))
                ps_name = vmess_config.get('ps', '')
                node_name = unquote(ps_name) if ps_name else ''
            else:
                parts = node_url.split('#', 1)
                node_name = unquote(parts[1]) if len(parts) > 1 and parts[1] else ''
            
            if not node_name:
                server = self.get_server_from_node(node_url)
                return f"节点_{server}" if server else "未知节点"
            
            region = self.get_node_region(node_name)
            return region if region else node_name
        except Exception as e:
            print(f"❌ 节点名称解析失败: {e}")
            sys.stdout.flush()
            with open(DEBUG_LOG_PATH, 'a', encoding='utf-8') as f:
                f.write(f"节点 URL: {node_url}, 错误: {str(e)}\n")
            return "解析失败节点"

    def get_server_from_node(self, node_url):
        try:
            if node_url.startswith('vmess://'):
                config_part = node_url.split('://')[1].split('#')[0]
                padding = len(config_part) % 4
                if padding:
                    config_part += '=' * (4 - padding)
                vmess_config = json.loads(base64.b64decode(config_part).decode('utf-8'))
                return vmess_config.get('add', '未知服务器')
            elif node_url.startswith(('trojan://', 'ss://', 'vless://')):
                parsed_url = urlparse(node_url)
                return parsed_url.hostname or '未知服务器'
            return None
        except Exception as e:
            print(f"❌ 服务器地址解析失败: {e}")
            sys.stdout.flush()
            return None

    def get_node_region(self, node_name):
        useless_keywords = ['剩余流量', '套餐到期', '使用前', '有任何问题', '续费官网', '防屏蔽官网', '老司机网址', '到期', '剩余']
        for keyword in useless_keywords:
            if keyword in node_name:
                return None

        region_keywords = {
            '香港': ['香港', 'HK', 'Hong Kong', 'HKG', '🇭🇰'],
            '新加坡': ['新加坡', 'SG', 'Singapore', 'SGP', '🇸🇬'],
            '日本': ['日本', 'JP', 'Japan', 'Tokyo', 'Osaka', '🇯🇵'],
            '美国': ['美国', 'US', 'United States', 'USA', 'Los Angeles', 'San Francisco', 'New York', '🇺🇸'],
            '台湾': ['台湾', 'TW', 'Taiwan', 'Taipei', '🇹🇼']
        }

        node_name_lower = node_name.lower()
        for region, keywords in region_keywords.items():
            for keyword in keywords:
                if keyword.lower() in node_name_lower:
                    return region
        return None

    def filter_and_rename_nodes(self, nodes):
        print("🔍 信息过滤中……")
        sys.stdout.flush()
        priority_regions = ['香港', '新加坡', '日本', '台湾', '美国']
        irrelevant_keywords = ['官网', '地址', '流量', '续费', '网址', '付费', '体验', '到期', '更新', '咨询', 'TG']
        
        filtered_nodes = []
        name_count = {}
        
        for node in nodes:
            decoded_name = self.get_node_name(node)
            if any(kw.lower() in decoded_name.lower() for kw in irrelevant_keywords):
                continue
            if self.get_node_region(decoded_name) not in priority_regions:
                continue
            
            if decoded_name in name_count:
                name_count[decoded_name] += 1
                unique_name = f"{decoded_name}-{name_count[decoded_name]}"
            else:
                name_count[decoded_name] = 0
                unique_name = decoded_name
            
            filtered_nodes.append((node, unique_name))
        
        print(f"✅ 找到 {len(filtered_nodes)} 条信息")
        sys.stdout.flush()
        return filtered_nodes

    def parse_node_to_clash(self, node_url, proxy_name):
        if node_url.startswith('vmess://'):
            try:
                config_part = node_url.split('://')[1].split('#')[0]
                padding = len(config_part) % 4
                if padding:
                    config_part += '=' * (4 - padding)
                vmess_config = json.loads(base64.b64decode(config_part).decode('utf-8', errors='ignore'))
                proxy_config = {
                    'name': proxy_name,
                    'type': 'vmess',
                    'server': vmess_config.get('add', ''),
                    'port': int(vmess_config.get('port', 0)),
                    'uuid': vmess_config.get('id', ''),
                    'alterId': int(vmess_config.get('aid', 0)),
                    'cipher': vmess_config.get('scy', 'auto'),
                    'udp': True,
                    'tls': str(vmess_config.get('tls')).lower() == 'tls',
                    'skip-cert-verify': True
                }
                if 'net' in vmess_config:
                    proxy_config['network'] = vmess_config['net']
                    if vmess_config['net'] == 'ws':
                        proxy_config['ws-opts'] = {
                            'path': vmess_config.get('path', '/'),
                            'headers': {'Host': vmess_config.get('host', proxy_config['server'])}
                        }
                if proxy_config.get('tls'):
                    proxy_config['servername'] = vmess_config.get('host', proxy_config['server'])
                return proxy_config
            except Exception as e:
                print(f"❌ 解析VMess节点失败: {e}")
                sys.stdout.flush()
                with open(DEBUG_LOG_PATH, 'a', encoding='utf-8') as f:
                    f.write(f"节点 URL: {node_url}, 错误: {str(e)}\n")
                return None
        elif node_url.startswith('trojan://'):
            try:
                parsed_url = urlparse(node_url)
                proxy_config = {
                    'name': proxy_name,
                    'type': 'trojan',
                    'server': parsed_url.hostname,
                    'port': parsed_url.port,
                    'password': parsed_url.username,
                    'udp': True,
                    'sni': parse_qs(parsed_url.query).get('sni', [parsed_url.hostname])[0],
                    'skip-cert-verify': True
                }
                return proxy_config
            except Exception as e:
                print(f"❌ 解析Trojan节点失败: {e}")
                sys.stdout.flush()
                with open(DEBUG_LOG_PATH, 'a', encoding='utf-8') as f:
                    f.write(f"节点 URL: {node_url}, 错误: {str(e)}\n")
                return None
        elif node_url.startswith('ss://'):
            try:
                parsed_url = urlparse(node_url)
                user_info_b64 = parsed_url.username
                padding = len(user_info_b64) % 4
                if padding:
                    user_info_b64 += '=' * (4 - padding)
                decoded_user_info = base64.urlsafe_b64decode(user_info_b64).decode('utf-8')
                cipher, password = decoded_user_info.split(':', 1)
                proxy_config = {
                    'name': proxy_name,
                    'type': 'ss',
                    'server': parsed_url.hostname,
                    'port': parsed_url.port,
                    'cipher': cipher,
                    'password': password,
                    'udp': True
                }
                return proxy_config
            except Exception as e:
                print(f"❌ 解析SS节点失败: {e}")
                sys.stdout.flush()
                with open(DEBUG_LOG_PATH, 'a', encoding='utf-8') as f:
                    f.write(f"节点 URL: {node_url}, 错误: {str(e)}\n")
                return None
        return None

    def generate_clash_config(self, renamed_nodes):
        print("🔍 信息筛选中……")
        sys.stdout.flush()
        config_template = {
            'dns': {
                'enable': True,
                'nameserver': ['119.29.29.29', '223.5.5.5'],
                'nameserver-policy': {
                    'ChinaClassical,Apple,SteamCN,geosite:cn': ['tls://1.12.12.12', '223.5.5.5']
                },
                'fallback': ['8.8.8.8', '1.1.1.1', 'tls://dns.google:853', 'tls://1.0.0.1:853']
            },
            'proxies': [],
            'proxy-groups': [
                {'name': '🚀 节点选择', 'type': 'select', 'proxies': []},
                {'name': '🎯 全球直连', 'type': 'select', 'proxies': ['DIRECT']}
            ],
            'rules': [
                'MATCH,🚀 节点选择'
            ]
        }

        proxy_names = []
        valid_nodes_info = []
        for node_url, unique_name in renamed_nodes:
            region = self.get_node_region(unique_name)
            if region is None:
                continue
            proxy_config = self.parse_node_to_clash(node_url, unique_name)
            if proxy_config:
                config_template['proxies'].append(proxy_config)
                proxy_names.append(unique_name)
                valid_nodes_info.append((unique_name, region))

        region_groups = {}
        for proxy_name, region in valid_nodes_info:
            if region not in region_groups:
                region_groups[region] = []
            region_groups[region].append(proxy_name)

        region_order = ['香港', '新加坡', '日本', '台湾', '美国']
        lb_groups = []
        for region in region_order:
            if region in region_groups and len(region_groups[region]) >= 2:
                lb_group_name = f'⚖️ 負載均衡_{region}'
                lb_group = {
                    'name': lb_group_name,
                    'type': 'load-balance',
                    'strategy': 'consistent-hashing',
                    'proxies': sorted(region_groups[region])
                }
                lb_groups.append(lb_group)

        node_select_proxies = []
        for region in region_order:
            lb_group_name = f'⚖️ 負載均衡_{region}'
            if any(lb['name'] == lb_group_name for lb in lb_groups):
                node_select_proxies.append(lb_group_name)

        for region in region_order:
            if region in region_groups:
                for proxy_name in sorted(region_groups[region]):
                    node_select_proxies.append(proxy_name)

        config_template['proxy-groups'][0]['proxies'] = node_select_proxies
        for lb_group in lb_groups:
            config_template['proxy-groups'].insert(1, lb_group)

        return config_template

    def save_clash_config(self, config, file_path):
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
            print(f"文件已保存至本地: {file_path}")
            sys.stdout.flush()
            return True
        except Exception as e:
            print(f"❌ 保存Clash配置失败: {e}")
            sys.stdout.flush()
            return False

def main():
    print("=== 娱乐工具⚙️ ===")
    sys.stdout.flush()
    
    netcut = NetcutSubscription()
    subscription_links = netcut.get_note_info("负载均衡", "114514")
    
    if not subscription_links:
        print("❌ 未获取到任何订阅链接，程序结束")
        sys.stdout.flush()
        return
    
    processor = NodeProcessor()
    all_nodes = []
    for url in subscription_links:
        nodes = processor.parse_subscribe_url(url)
        all_nodes.extend(nodes)
    
    if not all_nodes:
        print("❌ 未解析出任何节点，程序结束")
        sys.stdout.flush()
        return
    
    filtered_nodes = processor.filter_and_rename_nodes(all_nodes)
    
    if not filtered_nodes:
        print("❌ 未找到匹配默认地区的节点，程序结束")
        sys.stdout.flush()
        return
    
    clash_config = processor.generate_clash_config(filtered_nodes)
    processor.save_clash_config(clash_config, GENERATED_CLASH_CONFIG_PATH)

if __name__ == "__main__":
    main()
