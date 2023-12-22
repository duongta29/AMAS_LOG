import requests
import hashlib
import os
import json
import configparser
import time
import queue
import threading

config = configparser.ConfigParser()
config.read('config.ini')
report_folder = config.get("path", "report_folder")
sample_folder = config.get("path", "sample_folder")
data_queue = queue.Queue()

def get_auth_token(login, password):
    url = 'http://10.11.101.133:3344/api/auth/login'
    headers = {'Content-Type': 'application/json'}
    payload = {
        'login': login,
        'password': password
    }
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200:
        data = response.json()
        token = data.get('token')
        return token
    else:
        print('Failed to authenticate. Status code:', response.status_code)
        return None
    

def upload_and_get_sha256(file_path, token):
    # Địa chỉ API
    url = "http://10.11.101.133:3344/api/file"

    # Đặt thông tin file và các tùy chọn
    files = {
        'file': open(file_path, 'rb')
    }
    options = {
        "upload_as": "*",
        "attributes": [],
        "config": "{\"platform\":3,\"mode\":\"multi-tasking\"}",
        "platform": 0,
        "mode": 1
    }

    # Đặt header chứa mã thông báo xác thực
    headers = {
        'Authorization': f'Bearer {token}'
    }

    try:
        # Gửi yêu cầu POST đến API
        response = requests.post(url, files=files, data=options, headers=headers)
        response.raise_for_status()  # Nếu có lỗi, raise exception

        # Lấy thông tin mã sha256 từ phản hồi API
        json_response = response.json()
        sha256 = json_response['sha256']
        return sha256

    except requests.exceptions.RequestException as e:
        print(f"Yêu cầu gửi file thất bại: {e}")
        return None

def get_file_paths(folder_path):
    file_paths = []  # Danh sách đường dẫn tệp
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)  # Đường dẫn tệp
            file_paths.append(file_path)
    return file_paths

# def get_sha256():
#     with open("tokens.json", "r") as file:
#         data = json.load(file)
#         return data
    
def get_karton_analysis_result(sha256, token):
    url = f"http://10.11.101.133:3344/api/object/{sha256}/karton"
    headers = {
        "Authorization": f"Bearer {token}"
    }

    # Thay thế {sha256} và {token} trong URL và header
    # url = url.replace("{sha256}", sha256)
    headers["Authorization"] = headers["Authorization"]

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        amas_report = result['analyses'][0]["amas_report"]
        # print(result)
        return amas_report
    else:
        print("Error:", response.status_code)
        return None

def save_token(sample_folder):
    login = 'aidev'
    password = 'Ncs@2023'
    file_paths = get_file_paths(sample_folder)
    file_paths = file_paths[9346:]
    data = {}
    with open("file_done.txt", 'r') as file:
        file_done = [line.strip() for line in file]
    for file_path in file_paths:
        file_name = os.path.basename(file_path)
        if file_name not in file_done:
            data_txt = {}
            token = get_auth_token(login, password)
            if token:
                print("token: ", token)
                sha256 = upload_and_get_sha256(file_path, token)
                if sha256:
                    print("sha256: ",sha256)
                    data[sha256] = token
                    data_txt[sha256] = token
                    with open('tokens.txt', "a") as file:
                        json.dump(data_txt, file)
        else:
            continue
    with open('tokens.json', "w") as json_file:
        json.dump(data, json_file)
  
save_token(sample_folder)