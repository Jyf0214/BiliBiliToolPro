import os
import json
import base64
import requests
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
from requests.auth import HTTPBasicAuth
from xml.etree import ElementTree


def download_json_files(webdav_url, local_dir, username, password):
    """从 WebDAV 服务下载所有 .json 文件到指定目录"""
    print("[INFO] 开始从 WebDAV 服务下载 JSON 文件...")
    
    # 发起 PROPFIND 请求获取文件列表
    response = requests.request(
        "PROPFIND", webdav_url, auth=HTTPBasicAuth(username, password)
    )
    
    # 检查响应状态
    if response.status_code != 207:
        raise Exception(f"[ERROR] WebDAV 服务无法访问: 状态码 {response.status_code}")

    # 解析返回的 XML 响应
    try:
        tree = ElementTree.fromstring(response.text)
        namespaces = {'d': 'DAV:'}
        files = [element.text.split("/")[-1] for element in tree.findall(".//d:href", namespaces) if element.text.endswith(".json")]
    except ElementTree.ParseError as e:
        raise Exception(f"[ERROR] 解析 WebDAV 响应失败: {e}")

    if not files:
        raise Exception("[WARNING] 未找到任何 JSON 文件，检查 WebDAV 服务目录。")

    # 创建本地存储目录
    if not os.path.exists(local_dir):
        os.makedirs(local_dir)

    # 下载 JSON 文件
    for file in files:
        file_url = f"{webdav_url}/{file}"
        local_path = os.path.join(local_dir, file)
        try:
            file_response = requests.get(file_url, auth=HTTPBasicAuth(username, password))
            if file_response.status_code == 200:
                with open(local_path, "wb") as f:
                    f.write(file_response.content)
                print(f"[INFO] 成功下载文件: {file}")
            else:
                print(f"[WARNING] 下载失败: 文件 {file}, 状态码 {file_response.status_code}")
        except Exception as e:
            print(f"[ERROR] 下载文件 {file} 过程中发生错误: {e}")


def extract_cookies_from_file(file_name):
    """从 JSON 文件提取 Cookies"""
    with open(file_name, 'r', encoding='utf-8') as file:
        data = json.load(file)
    cookies = data.get("cookie_info", {}).get("cookies", [])
    return "; ".join(f"{cookie['name']}={cookie['value']}" for cookie in cookies)


def encrypt_secret(secret, public_key_base64):
    """使用 GitHub 提供的公钥加密 Secret"""
    try:
        # 解码 Base64 编码的公钥
        public_key_bytes = base64.b64decode(public_key_base64)
        
        # 加载公钥
        public_key_obj = serialization.load_pem_public_key(public_key_bytes)
        
        # 使用公钥加密 Secret
        encrypted_secret = public_key_obj.encrypt(
            secret.encode("utf-8"),
            OAEP(mgf=MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None)
        )
        return encrypted_secret
    except Exception as e:
        print(f"[ERROR] 公钥加密失败: {e}")
        raise


def upload_github_secret(repo_owner, repo_name, secret_name, secret_value, pat):
    """上传 Secret 到 GitHub"""
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/secrets/public-key"
    headers = {"Authorization": f"token {pat}"}
    
    # 获取公钥
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"[ERROR] 无法获取公钥: 状态码 {response.status_code}")
    public_key_data = response.json()
    public_key_base64 = public_key_data["key"]
    key_id = public_key_data["key_id"]

    # 打印公钥 Base64 编码的一部分，帮助调试
    print(f"[INFO] 获取到公钥: {public_key_base64[:100]}...")  # 只打印公钥的前100个字符

    # 加密 Secret
    encrypted_secret = encrypt_secret(secret_value, public_key_base64)
    
    # 上传加密后的 Secret
    secret_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/secrets/{secret_name}"
    payload = {
        "encrypted_value": encrypted_secret.decode("utf-8"),
        "key_id": key_id,
    }
    upload_response = requests.put(secret_url, headers=headers, json=payload)
    if upload_response.status_code != 201:
        raise Exception(f"[ERROR] 上传 Secret 失败: 状态码 {upload_response.status_code}")
    print(f"[INFO] 成功上传 Secret: {secret_name}")


def main():
    print("[INFO] 开始执行脚本...")
    
    webdav_url = os.getenv("WEBDAV_URL")
    username = os.getenv("WEBDAV_USERNAME")
    password = os.getenv("WEBDAV_PASSWORD")
    pat = os.getenv("GITHUB_PAT")
    repo_owner = "Jyf0214"
    repo_name = "BiliBiliToolPro"
    local_dir = "downloaded_json"

    try:
        # 下载 JSON 文件
        download_json_files(webdav_url, local_dir, username, password)

        # 提取并上传 Secret
        for idx, file_name in enumerate(os.listdir(local_dir), start=1):
            if file_name.endswith(".json"):
                local_path = os.path.join(local_dir, file_name)
                cookie_string = extract_cookies_from_file(local_path)
                secret_name = f"COOKIESTR{idx if idx > 1 else ''}"
                upload_github_secret(repo_owner, repo_name, secret_name, cookie_string, pat)
        print("[INFO] 脚本执行完成！")
    except Exception as e:
        print(f"[ERROR] 脚本执行失败: {e}")


if __name__ == "__main__":
    main()