import os
import time
import requests
import json
import urllib
import hashlib
from base64 import b64encode
from nacl import encoding, public

# --- GitHub Secrets 更新函数 (无需修改) ---
def get_repo_public_key(session, repo_full_name):
    url = f"https://api.github.com/repos/{repo_full_name}/actions/secrets/public-key"
    response = session.get(url)
    response.raise_for_status()
    return response.json()

def encrypt_secret(public_key_value, secret_value):
    public_key = public.PublicKey(public_key_value.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return b64encode(encrypted).decode("utf-8")

def update_github_secret(session, repo_full_name, secret_name, secret_value, key_id):
    url = f"https://api.github.com/repos/{repo_full_name}/actions/secrets/{secret_name}"
    encrypted_value = encrypt_secret(key_id['key'], secret_value)
    payload = {"encrypted_value": encrypted_value, "key_id": key_id['key_id']}
    response = session.put(url, json=payload)
    response.raise_for_status()
    if response.status_code == 201:
        print(f"✔️ Secret '{secret_name}' 已成功创建。")
    elif response.status_code == 204:
        print(f"✔️ Secret '{secret_name}' 已成功更新。")

# --- Bilibili API 相关函数 (无需修改) ---
def tvsign(params, appkey='4409e2ce8ffd12b8', appsec='59b43e04ad6965f34319062b478f83dd'):
    params.update({'appkey': appkey})
    params = dict(sorted(params.items()))
    query = urllib.parse.urlencode(params)
    sign = hashlib.md5((query + appsec).encode()).hexdigest()
    params.update({'sign': sign})
    return params

def get_cookies_dict(cookies_list):
    cookies = {cookie['name']: cookie['value'] for cookie in cookies_list}
    return {
        'BILI_JCT': cookies.get('bili_jct'),
        'SESSDATA': cookies.get('SESSDATA'),
        'DEDEUSERID': cookies.get('DedeUserID'),
        'COOKIESTR': '; '.join([f"{c['name']}={c['value']}" for c in cookies_list])
    }

# --- 主逻辑 ---
def main():
    # 从环境变量中读取配置
    try:
        PAT = os.environ['PAT']
        github_repo = os.environ['GITHUB_REPOSITORY']
    except KeyError as e:
        print(f"❌ 错误: 缺少必要的环境变量: {e}。请确保在 GitHub Actions 中正确设置了 Secrets。")
        return

    # 从环境变量中收集所有 Bilibili 账号信息
    bili_users_info = []
    for i in range(1, 100):  # 最多支持99个账号
        bili_info_str = os.environ.get(f'BILI_INFO_{i}')
        if bili_info_str:
            try:
                bili_users_info.append(json.loads(bili_info_str))
            except json.JSONDecodeError:
                print(f"❌ 错误: 环境变量 BILI_INFO_{i} 的值不是一个有效的 JSON 字符串。")
        else:
            break  # 当找不到 BILI_INFO_{i} 时，停止搜索

    if not bili_users_info:
        print("⚠️ 警告: 未在环境变量中找到任何 Bilibili 账号信息 (例如 BILI_INFO_1)。")
        return

    # 创建一个带认证的 requests session
    gh_session = requests.Session()
    gh_session.headers.update({
        "Authorization": f"token {PAT}",
        "Accept": "application/vnd.github.v3+json"
    })

    # 获取仓库的 public key
    try:
        print(f"正在获取仓库 {github_repo} 的 public key...")
        public_key_info = get_repo_public_key(gh_session, github_repo)
        print("✔️ Public key 获取成功。")
    except requests.exceptions.RequestException as e:
        print(f"❌ 无法获取仓库 public key: {e}")
        return

    # 遍历每个账号进行处理
    for index, saveInfo in enumerate(bili_users_info, start=1):
        print(f"\n--- 正在处理账号 {index} ---")
        
        # 刷新 Bilibili Token
        print("正在刷新 Bilibili Token...")
        rsp = requests.post("https://passport.bilibili.com/api/v2/oauth2/refresh_token", params=tvsign({
            'access_key': saveInfo['token_info']['access_token'],
            'refresh_token': saveInfo['token_info']['refresh_token'],
            'ts': int(time.time())
        }), headers={
            "content-type": "application/x-www-form-urlencoded",
            "user-agent": "Mozilla/5.0"
        })

        try:
            rsp_data = rsp.json()
        except json.JSONDecodeError:
            print(f'❌ 解析 Bilibili API 响应失败。响应内容: {rsp.text}')
            continue

        if rsp_data.get('code') == 0:
            expires_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(rsp_data['ts'] + int(rsp_data['data']['token_info']['expires_in'])))
            print(f"✔️ Token 刷新成功, 有效期至 {expires_time}")

            # 准备上传到 GitHub Secrets
            print("正在准备上传 Secrets...")
            cookies_to_upload = get_cookies_dict(rsp_data['data']['cookie_info']['cookies'])
            suffix = f"_{index}" if index > 1 else ""
            
            secrets_map = {
                f"COOKIESTR{suffix}": cookies_to_upload.get('COOKIESTR'),
                f"BILI_JCT{suffix}": cookies_to_upload.get('BILI_JCT'),
                f"SESSDATA{suffix}": cookies_to_upload.get('SESSDATA'),
                f"DEDEUSERID{suffix}": cookies_to_upload.get('DEDEUSERID')
            }

            for name, value in secrets_map.items():
                if value:
                    try:
                        update_github_secret(gh_session, github_repo, name, value, public_key_info)
                    except requests.exceptions.RequestException as e:
                        print(f"❌ 上传 Secret '{name}' 失败: {e.response.text}")
                else:
                    print(f"⚠️ 警告: 未找到值，跳过上传 Secret '{name}'。")

            # 重要：将包含新 refresh_token 的完整 JSON 也更新到 Secret 中
            # 这样即使用户的 refresh_token 过期，也可以从这里找回最新的
            new_save_info = {
                'update_time': rsp_data['ts'] * 1000,
                'token_info': rsp_data['data']['token_info'],
                'cookie_info': rsp_data['data']['cookie_info']
            }
            new_info_secret_name = f"BILI_JSON_DATA{suffix}"
            new_info_json_str = json.dumps(new_save_info, separators=(',', ':'))
            try:
                update_github_secret(gh_session, github_repo, new_info_secret_name, new_info_json_str, public_key_info)
                print(f"ℹ️  注意: 最新的完整登录信息已保存到 Secret '{new_info_secret_name}'。如果原始 refresh_token 失效，请使用此值更新您的 BILI_INFO_{index} Secret。")
            except Exception as e:
                print(f"❌ 上传最新登录信息 '{new_info_secret_name}' 失败: {e}")

        else:
            print(f"❌ Bilibili Token 刷新失败 (账号 {index}): {rsp_data.get('message', '未知错误')}")
            continue

if __name__ == "__main__":
    main()