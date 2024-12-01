import os
import json
import requests
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
from requests.auth import HTTPBasicAuth


def download_json_files(webdav_url, local_dir, username, password):
    """从 WebDAV 服务下载所有 .json 文件到指定目录"""
    response = requests.request(
        "PROPFIND", webdav_url, auth=HTTPBasicAuth(username, password)
    )
    if response.status_code != 207:
        raise Exception(f"WebDAV 服务无法访问: {response.status_code}")
    files = [line.split("</D:href>")[0].split("/")[-1]
             for line in response.text.split("\n") if ".json" in line]
    if not os.path.exists(local_dir):
        os.makedirs(local_dir)
    for file in files:
        file_url = f"{webdav_url}/{file}"
        local_path = os.path.join(local_dir, file)
        file_response = requests.get(file_url, auth=HTTPBasicAuth(username, password))
        if file_response.status_code == 200:
            with open(local_path, "wb") as f:
                f.write(file_response.content)
        else:
            print(f"下载失败: {file}")


def extract_cookies_from_file(file_name):
    """从 JSON 文件提取 Cookies"""
    with open(file_name, 'r', encoding='utf-8') as file:
        data = json.load(file)
    cookies = data.get("cookie_info", {}).get("cookies", [])
    return "; ".join(f"{cookie['name']}={cookie['value']}" for cookie in cookies)


def encrypt_secret(secret, public_key):
    """使用 GitHub 提供的公钥加密 Secret"""
    public_key_obj = serialization.load_pem_public_key(public_key.encode("utf-8"))
    return public_key_obj.encrypt(
        secret.encode("utf-8"),
        OAEP(mgf=MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None)
    )


def upload_github_secret(repo_owner, repo_name, secret_name, secret_value, pat):
    """上传 Secret 到 GitHub"""
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/secrets/public-key"
    headers = {"Authorization": f"token {pat}"}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"无法获取公钥: {response.status_code}")
    public_key_data = response.json()
    public_key = public_key_data["key"]
    key_id = public_key_data["key_id"]
    encrypted_secret = encrypt_secret(secret_value, public_key)
    secret_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/secrets/{secret_name}"
    payload = {
        "encrypted_value": encrypted_secret.decode("utf-8"),
        "key_id": key_id,
    }
    upload_response = requests.put(secret_url, headers=headers, json=payload)
    if upload_response.status_code != 201:
        raise Exception(f"上传 Secret 失败: {upload_response.status_code}")


def main():
    webdav_url = os.getenv("WEBDAV_URL")
    username = os.getenv("WEBDAV_USERNAME")
    password = os.getenv("WEBDAV_PASSWORD")
    pat = os.getenv("GITHUB_PAT")
    repo_owner = "Jyf0214"
    repo_name = "BiliBiliToolPro"
    local_dir = "downloaded_json"

    # 下载 JSON 文件
    download_json_files(webdav_url, local_dir, username, password)

    # 提取并上传 Secret
    for idx, file_name in enumerate(os.listdir(local_dir), start=1):
        if file_name.endswith(".json"):
            local_path = os.path.join(local_dir, file_name)
            cookie_string = extract_cookies_from_file(local_path)
            secret_name = f"COOKIESTR{idx if idx > 1 else ''}"
            upload_github_secret(repo_owner, repo_name, secret_name, cookie_string, pat)


if __name__ == "__main__":
    main()
