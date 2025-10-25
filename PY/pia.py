
import json
import requests
import base64

def fetch_data(url):
    try:
        response = requests.get(url)  
        response.raise_for_status()
        raw_data = response.text
        json_data = raw_data.split(']')[0] + ']'
        return json.loads(json_data)
    except requests.exceptions.RequestException as err:
        print(f"请求错误: {err}")
    except json.JSONDecodeError as json_err:
        print(f"JSON解析错误: {json_err}")
    return None

def get_json_data(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as err:
        print(f"请求错误: {err}")
    return []

def encode_ss_info(method, password, server, server_port, remarks):
    base64_info = f"{method}:{password}@{server}:{server_port}"
    base64_encoded = base64.b64encode(base64_info.encode('utf-8')).decode('utf-8')
    return f"ss://{base64_encoded}#{remarks}"

def encode_ss_link(cipher, key, host, port, region):
    cipher_key = f"{cipher}:{key}"
    encoded_cipher_key = base64.b64encode(cipher_key.encode()).decode()
    return f"ss://{encoded_cipher_key}@{host}:{port}#{region}"

url1 = "https://raw.githubusercontent.com/DemanNL/PIA-shadowsocks-android-guide/main/profiles.json"
url2 = "https://raw.githubusercontent.com/Minecraftpe2007/joshua/master/piavpn.json"

data1 = get_json_data(url1)
data3 = get_json_data(url2)

url3 = "https://serverlist.piaservers.net/shadow_socks"
data2 = fetch_data(url3)

ss_urls = set()

for data in [data1, data3]:
    for item in data:
        ss_url = encode_ss_info(
            item['method'],
            item['password'],
            item['server'],
            item['server_port'],
            item['remarks']
        )
        ss_urls.add(ss_url)

if data2:
    for item in data2:
        ss_link = encode_ss_link(
            item['cipher'],
            item['key'],
            item['host'],
            item['port'],
            item['region']
        )
        ss_urls.add(ss_link)

with open('pia.txt', 'w') as f:
    for url in ss_urls:
        f.write(url + '\n')
        print(url)
