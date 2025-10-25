#白鲸加速器刷邀请（切换代理换IP）
import requests
import time
import random
import string
from threading import Thread

def ranEmail():
    random_str = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(random.randint(5, 8)))
    email = random_str + "@gmail.com"
    return email

def ranDeviceId():
    device_id = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(len("rk_dbf7a4a5b8294d988ea07ccd1b06e82b")))
    return device_id

url = "https://co01.jurasic.net/account/register"

def send_request():
    for i in range(20):
        params = {
            "platform": "2",
            "api_version": "14",
            "app_version": "1.45",
            "lang": "zh",
            "_key": "",
            "market_id": "1000",
            "pkg": "com.bjchuhai",
            "device_id": ranDeviceId(),
            "model": "NX709S/nubia",
            "sys_version": "9",
            "ts": str(int(time.time() * 1000)),
            "sub_pkg": "com.bjchuhai",
            "version_code": "45"
        }
        body = {
            "passwd": "e10adc3949ba59abbe56e057f20f883e",
            "invite_code": "3AETX",##这里是邀请码
            "email": ranEmail()
        }
        response = requests.post(url, params=params, data=body)
        time.sleep(random.uniform(2, 3))
        print("Status Code:", response.status_code)
        print("Response Text:", response.text)

if __name__ == "__main__":
    threads = []
    for _ in range(5):  # 创建5个线程
        thread = Thread(target=send_request)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
