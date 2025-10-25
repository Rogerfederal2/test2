import imaplib
import email
from email.header import decode_header
import re
from bs4 import BeautifulSoup

def decode_email_subject(subject):
    """解码邮件主题，处理编码格式"""
    decoded_subject = decode_header(subject)[0][0]
    encoding = decode_header(subject)[0][1]
    if isinstance(decoded_subject, bytes):
        return decoded_subject.decode(encoding or 'utf-8', errors='ignore')
    return decoded_subject

def decode_email_body(msg):
    """解码邮件正文，优先提取 text/html（解析为纯文本），若无则回退到 text/plain"""
    html_part = None
    plain_part = None

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if content_type == "text/html" and "attachment" not in content_disposition:
                html_part = part.get_payload(decode=True).decode(errors='ignore')
            elif content_type == "text/plain" and "attachment" not in content_disposition:
                plain_part = part.get_payload(decode=True).decode(errors='ignore')
    else:
        content_type = msg.get_content_type()
        if content_type == "text/html":
            html_part = msg.get_payload(decode=True).decode(errors='ignore')
        elif content_type == "text/plain":
            plain_part = msg.get_payload(decode=True).decode(errors='ignore')

    # 优先处理 HTML 格式，解析为纯文本
    if html_part:
        soup = BeautifulSoup(html_part, 'html.parser')
        return soup.get_text().strip()
    return (plain_part if plain_part else "").strip()

def extract_verification_code(body):
    """从邮件正文中提取 6 位数字验证码"""
    # 使用正则表达式匹配 6 位数字
    match = re.search(r'\b\d{6}\b', body)
    if match:
        return match.group(0)
    return None

def connect_to_gmail_imap():
    # Gmail IMAP 服务器设置
    IMAP_SERVER = "imap.gmail.com"
    IMAP_PORT = 993

    try:
        # 获取用户输入的邮箱
        email_address = input("请输入您的 Gmail 邮箱地址: ")
        
        # 获取密码（使用普通 input，支持直接输入和粘贴）
        print("请输入您的 Gmail 密码（或应用专用密码）。注意：输入可能会显示，建议在安全环境下操作。")
        password = input("密码: ").strip()  # 清理输入，去除换行符或多余空格

        # 调试：显示输入的密码长度（仅用于测试）
        print(f"调试：输入的密码长度为 {len(password)} 字符")
        # print(f"调试：输入的密码是 '{password}'")  # 取消注释以查看实际密码，仅限测试

        # 建立 IMAP 连接（使用 SSL）
        print("尝试连接 Gmail IMAP 服务器...")
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)

        # 登录邮箱
        mail.login(email_address, password)
        print("成功登录 Gmail IMAP 服务器！")

        # 选择收件箱
        mail.select("INBOX")

        # 搜索所有邮件（按最新排序）
        status, messages = mail.search(None, "ALL")
        if status != "OK":
            print("无法搜索邮件。")
            mail.logout()
            return

        # 获取最新邮件 ID
        email_ids = messages[0].split()
        if not email_ids:
            print("收件箱为空，无法获取邮件。")
            mail.logout()
            return

        latest_email_id = email_ids[-1]  # 最新邮件
        status, msg_data = mail.fetch(latest_email_id, "(RFC822)")
        if status != "OK":
            print(f"无法获取最新邮件（ID: {latest_email_id.decode()}）。")
            mail.logout()
            return

        # 解析最新邮件
        msg = email.message_from_bytes(msg_data[0][1])

        # 获取邮件主题
        subject = decode_email_subject(msg["Subject"])
        # 获取发件人
        from_address = msg.get("From")
        # 获取日期
        date = msg.get("Date")
        # 获取正文（优先 text/html，解析为纯文本）
        body = decode_email_body(msg)
        # 提取验证码
        verification_code = extract_verification_code(body)

        # 输出最新邮件详情
        print("\n最新邮件详情（优先提取 text/html 格式正文，解析为纯文本）：")
        print("-" * 50)
        print(f"邮件 ID: {latest_email_id.decode()}")
        print(f"主题: {subject}")
        print(f"发件人: {from_address}")
        print(f"日期: {date}")
        print("正文（前 200 字符）：")
        print(body[:200] + ("..." if len(body) > 200 else ""))
        print("-" * 50)

        # 输出验证码
        if verification_code:
            print(f"从最新邮件（ID: {latest_email_id.decode()}）提取的验证码：{verification_code}")
        else:
            print(f"最新邮件（ID: {latest_email_id.decode()}）中未找到验证码。")

        # 退出并关闭连接
        mail.logout()
        print("已断开 IMAP 服务器连接。")

    except imaplib.IMAP4.error as e:
        print(f"IMAP 错误：{e}")
    except Exception as e:
        print(f"连接或处理失败：{e}")

if __name__ == "__main__":
    print("Gmail IMAP 连接工具")
    print("注意：如果启用了两步验证，请使用 Google 应用专用密码。")
    connect_to_gmail_imap()
