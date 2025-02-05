import os
import requests
from github import Github

# 读取本地的 data.txt 文件
def read_data_file(filepath):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"文件 '{filepath}' 不存在")

    data = {}
    with open(filepath, 'r') as f:
        for line_number, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):  # 忽略空行和注释行
                continue
            if '=' not in line:
                print(f"警告：第 {line_number} 行格式错误，已忽略：'{line}'")
                continue
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip()
            if not key or not value:
                print(f"警告：第 {line_number} 行键或值为空，已忽略：'{line}'")
                continue
            data[key] = value
    return data

# 更新 GitHub 仓库的 Secrets
def update_github_secrets(repo_name, secrets_data, github_token):
    g = Github(github_token)
    repo = g.get_user().get_repo(repo_name)

    for name, value in secrets_data.items():
        try:
            # 尝试获取已存在的 secret
            secret = repo.get_secret(name)
            # 更新 secret 的值
            try:
                secret.update(value)
                print(f"成功更新 Secret: {name}")
            except Exception as e:
                print(f"更新 Secret {name} 失败: {e}")

        except Exception as e:
            if e.status == 404:
                # 如果 secret 不存在，则创建新的 secret
                try:
                    repo.create_secret(name, value)
                    print(f"成功创建 Secret: {name}")
                except Exception as e:
                    print(f"创建 Secret {name} 失败: {e}")
            else:
                print(f"获取或更新 Secret {name} 失败: {e}")

if __name__ == "__main__":
    # 从环境变量中读取配置
    repo_name = "Jyf0214/BiliBiliToolPro"
    github_token = os.environ.get("PAT") # 从名为 PAT 的环境变量读取 token
    data_filepath = os.environ.get("DATA_FILEPATH", "data.txt") # 默认值为 "data.txt"

    # 检查必要的环境变量是否已设置
    if not repo_name or not github_token:
        raise ValueError("请设置环境变量 GITHUB_REPO_NAME 和 PAT")

    try:
        # 读取 data.txt 文件
        secrets_data = read_data_file(data_filepath)

        # 更新 GitHub 仓库的 Secrets
        update_github_secrets(repo_name, secrets_data, github_token)
    except Exception as e:
        print(f"发生错误: {e}")