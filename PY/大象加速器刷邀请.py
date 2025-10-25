import requests
import random
import string

for _ in range(100):
    # 设备ID
    abc = "rk_" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))

    # 邮箱
    email = ''.join(random.choices(string.ascii_lowercase, k=5)) + "@djj.cn"

    url = "http://139.224.27.183/account/register"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "139.224.27.183",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "User-Agent": "okhttp/3.5.0"
    }
    payload = {
        "platform": "2",
        "api_version": "14",
        "app_version": "1.1",
        "lang": "zh",
        "_key": "",
        "market_id": "6001",
        "pkg": "com.daxiangpro",
        "device_id": abc,
        "model": "SM-G9910/samsung",
        "sys_version": "13",
        "ts": "1709908220878",
        "sub_pkg": "com.daxiangpro",
        "version_code": "2",
        "passwd": "25d55ad283aa400af464c76d713c07ad",
        "invite_code": "QGKZ4",
        "email": email
    }

    response = requests.post(url, headers=headers, data=payload)

    print(response.text)
    print("-----------------")