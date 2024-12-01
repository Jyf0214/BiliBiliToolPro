import os
import json
import base64
import requests
from xml.etree import ElementTree
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_der_public_key
from requests.auth import HTTPBasicAuth


def download_json_files(webdav_url, local_dir, username, password):
    """从 WebDAV 服务下载所有 .json 文件到指定目录"""
    print("[INFO] 开始从 WebDAV 服务下载 JSON 文件...")
    
    response = requests.request("PROPFIND", webdav_url, auth=HTTPBasicAuth(username, password))
    if response.status_code != 207:
        raise Exception(f"[ERROR] WebDAV 服务无法访问: 状态码 {response.status_code}")
    
    try:
        tree = ElementTree.fromstring(response.text)
        namespaces = {'d': 'DAV:'}
        files = [element.text.split("/")[-1] for element in tree.findall(".//d:href", namespaces) if element.text.endswith(".json")]
    except ElementTree.ParseError as e:
        raise Exception(f"[ERROR] 解析 WebDAV 响应失败: {e}")
    
    if not files:
        raise Exception("[WARNING] 未找到任何 JSON 文件，检查 WebDAV 服务目录。")

    if not os.path.exists(local_dir):
        os.makedirs(local_dir)

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


def encrypt_secret(secret, public_key_data):
    """使用 GitHub 提供的公钥加密 Secret"""
    try:
        # 解析 base64 公钥数据为 DER 格式
        decoded_key = base64.b64decode(public_key_data)
        public_key = load_der_public_key(decoded_key)
    except Exception:
        raise ValueError("[ERROR] 无法加载公钥数据，确保公钥是有效的 base64 编码 DER 格式。")

    return base64.b64encode(
        public_key.encrypt(
            secret.encode("utf-8"),
            OAEP(mgf=MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None)
        )
    ).decode("utf-8")


def upload_github_secret(repo_owner, repo_name, secret_name, secret_value, pat):
    """上传 Secret 到 GitHub"""
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/secrets/public-key"
    headers = {"Authorization": f"token {pat}"}
    
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"[ERROR] 无法获取公钥: 状态码 {response.status_code}")
    
    public_key_data = response.json().get("key")
    key_id = response.json().get("key_id")
    if not public_key_data or not key_id:
        raise ValueError("[ERROR] 获取公钥失败，确保 API 返回数据格式正确。")

    encrypted_secret = encrypt_secret(secret_value, public_key_data)

    secret_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/secrets/{secret_name}"
    payload = {"encrypted_value": encrypted_secret, "key_id": key_id}
    upload_response = requests.put(secret_url, headers=headers, json=payload)
    if upload_response.status_code not in [201, 204]:
        raise Exception(f"[ERROR] 上传 Secret 失败: 状态码 {upload_response.status_code}, 响应内容: {upload_response.text}")
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
        download_json_files(webdav_url, local_dir, username, password)

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