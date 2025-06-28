import json
import os
import requests

def fetch_bing_images(run_type):
    url = f"https://www.bing.com/HPImageArchive.aspx?format=js&idx=0&n=8&mkt={run_type}"

    try:
        response = requests.get(url)
        response.raise_for_status()  # 检查请求是否成功
        data = response.json()  # 解析JSON数据

        return data  # 返回获取到的数据
    except requests.RequestException as e:
        print(f"请求出错: {e}")
        return None
    except ValueError as e:
        print(f"解析JSON出错: {e}")
        return None

def save_images_to_json(images, folder):
    if not os.path.exists(folder):
        os.makedirs(folder)  # 创建文件夹

    file_path = os.path.join(folder, 'bing_images.json')

    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(images, f, ensure_ascii=False, indent=4)  # 保存为JSON文件

    print(f"图像信息已保存到: {file_path}")

# 使用示例
if __name__ == "__main__":
    run_type = "zh-CN"  # 你可以根据需要修改语言/市场类型
    images_data = fetch_bing_images(run_type)

    if images_data and 'images' in images_data:
        save_images_to_json(images_data['images'], 'assets')  # 保存图像信息到assets文件夹