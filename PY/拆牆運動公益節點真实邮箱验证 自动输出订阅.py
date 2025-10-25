import requests
import time
import random
import string

BASE_URL = "https://edeyuan.com"
HEADERS = {'User-Agent': 'Mozilla/5.0'}

EMAIL = input("请输入你的注册邮箱: ").strip()
PASSWORD = ''.join(random.choices(string.ascii_letters + string.digits, k=10)) + "!"


def send_email_code(email):
    url = f"{BASE_URL}/api/v1/passport/comm/sendEmailVerify"
    data = {"email": email, "scene": "register"}
    try:
        resp = requests.post(url, headers=HEADERS, json=data, timeout=10).json()
        return resp.get("status") == "success"
    except Exception as e:
        print("❌ 发送验证码异常:", e)
        return False


def register(email, password, code):
    url = f"{BASE_URL}/api/v1/passport/auth/register"
    data = {
        "email": email,
        "password": password,
        "email_code": code,
        "invite_code": "mwCoUrlg"
    }
    try:
        resp = requests.post(url, headers={**HEADERS, "Content-Type": "application/json"}, json=data, timeout=10)
        result = resp.json()
        if result.get("status") == "success":
            return result.get("data", {}).get("auth_data")
        elif "邮箱已在系统中存在" in result.get("message", ""):
            return login(email, password)
        else:
            print("❌ 注册失败:", result.get("message"))
    except Exception as e:
        print("❌ 注册异常:", e)
    return None


def login(email, password):
    url = f"{BASE_URL}/api/v1/passport/auth/login"
    data = {"email": email, "password": password}
    try:
        resp = requests.post(url, headers={**HEADERS, "Content-Type": "application/json"}, json=data, timeout=10)
        result = resp.json()
        if result.get("status") == "success":
            return result.get("data", {}).get("auth_data")
        else:
            print("❌ 登录失败:", result.get("message"))
    except Exception as e:
        print("❌ 登录异常:", e)
    return None


def create_order(token, plan_id):
    url = f"{BASE_URL}/api/v1/user/order/save"
    headers = {'Authorization': token, 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': HEADERS['User-Agent']}
    data = {"plan_id": plan_id, "period": "year_price"}
    try:
        resp = requests.post(url, headers=headers, data=data, timeout=10)
        result = resp.json()
        if result.get("status") == "success":
            return result.get("data")
        else:
            print("❌ 创建订单失败:", result.get("message"))
    except Exception as e:
        print("❌ 创建订单异常:", e)
    return None


def checkout_order(token, trade_no):
    url = f"{BASE_URL}/api/v1/user/order/checkout"
    headers = {'Authorization': token, 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': HEADERS['User-Agent']}
    data = {"trade_no": trade_no}
    try:
        resp = requests.post(url, headers=headers, data=data, timeout=10)
        if resp.status_code == 200:
            return True
        else:
            print("❌ 结账失败:", resp.text)
    except Exception as e:
        print("❌ 结账异常:", e)
    return False


def get_subscribe_url(token):
    url = f"{BASE_URL}/api/v1/user/getSubscribe"
    headers = {'Authorization': token, 'User-Agent': HEADERS['User-Agent']}
    try:
        resp = requests.get(url, headers=headers, timeout=10).json()
        sub_url = resp.get("data", {}).get("subscribe_url")
        if sub_url:
            return sub_url
        else:
            print("❌ 获取订阅链接失败:", resp)
    except Exception as e:
        print("❌ 请求异常:", e)
    return None


if __name__ == "__main__":
    if send_email_code(EMAIL):
        code = input("请输入邮箱收到的验证码: ").strip()
        token = register(EMAIL, PASSWORD, code)
        if token:
            time.sleep(1)
            plan_id = 1
            trade_no = create_order(token, plan_id)
            if trade_no and checkout_order(token, trade_no):
                time.sleep(1)
                sub_url = get_subscribe_url(token)
                if sub_url:
                    print(sub_url)  # ✅ 最终只输出订阅链接
