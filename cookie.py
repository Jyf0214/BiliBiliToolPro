import os
import requests
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
        print("[WARNING] 未找到任何 JSON 文件，检查 WebDAV 服务目录。")
        return  # 直接返回，避免引发异常

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

def main():
    print("[INFO] 开始执行脚本...")

    webdav_url = os.getenv("WEBDAV_URL")
    username = os.getenv("WEBDAV_USERNAME")
    password = os.getenv("WEBDAV_PASSWORD")
    local_dir = "."

    try:
        # 下载 JSON 文件
        download_json_files(webdav_url, local_dir, username, password)
        print("[INFO] 脚本执行完成！")
    except Exception as e:
        print(f"[ERROR] 脚本执行失败: {e}")

if __name__ == "__main__":
    main()