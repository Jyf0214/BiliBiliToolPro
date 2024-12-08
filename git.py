import os
import subprocess

# 配置
repo_url = "git@github.com:Jyf0214/BiliBiliToolPro.git"
assets_dir = "assets"
git_username = "Jyf0214"
git_email = "jyf20100214@outlook.com"  # 使用你的 GitHub 邮箱

# 确保当前工作目录是正确的
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# 初始化 Git 仓库（如果还没有的话）
if not os.path.exists(".git"):
    subprocess.run(["git", "init"])

# 设置 Git 用户名和邮箱
subprocess.run(["git", "config", "--global", "user.name", git_username])
subprocess.run(["git", "config", "--global", "user.email", git_email])

# 添加远程仓库 origin（如果还没有的话）
try:
    subprocess.run(["git", "remote", "add", "origin", repo_url], check=True)
except subprocess.CalledProcessError:
    print("Remote origin already exists. Continuing with existing remote.")

# 添加、提交并推送到 GitHub
try:
    # 添加 assets 文件夹
    subprocess.run(["git", "add", assets_dir], check=True)
    # 提交更改
    subprocess.run(["git", "commit", "-m", "Update assets folder"], check=True)
    # 推送到远程仓库
    subprocess.run(["git", "push", "--force", "origin", "main"], check=True)
    print("Successfully pushed assets folder to GitHub.")
except subprocess.CalledProcessError as e:
    print(f"An error occurred: {e}")