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
status = config.get("status", "status")
data_queue = queue.Queue()


def get_auth_token(login, password):
    url = 'http://192.168.14.183:3344/api/auth/login'
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
    url = "http://192.168.14.183:3344/api/file"

    # Đặt thông tin file và các tùy chọn
    files = {
        'file': open(file_path, 'rb')
    }
    #upload to get emul
    options = {
    "upload_as": "*",
    "attributes": [],
    "config": '{"platform": 1, "mode": "multi-tasking"}'
}
    data = {'options': json.dumps(options)}

    # Đặt header chứa mã thông báo xác thực
    headers = {
        'Authorization': f'Bearer {token}'
    }

    try:
        # Gửi yêu cầu POST đến API
        response = requests.post(url, files=files, data=data, headers=headers)
        response.raise_for_status()  # Nếu có lỗi, raise exception

        # Lấy thông tin mã sha256 từ phản hồi API
        json_response = response.json()
        sha256 = json_response['sha256']
        return sha256

    except requests.exceptions.RequestException as e:
        print(f"Yêu cầu gửi file thất bại: {e}")
        return None
    
def reupload_file(file_path, token, sha256, platform):
    url = f'http://192.168.14.183:3344/api/object/{sha256}/karton'
    headers = {
        'Authorization': f'Bearer {token}'
    }
    config = {
    "config": f'{{ "execfile": "{sha256}", "emul":{{"basic": {{"os": "windows", "arch": "x86", "timeout": "60"}}, "advanced": {{"computername": "testpc", "username": "testuser", "number_processors": "5", "pid": "2000", "ram_size": "0xa00000", "majorversion": "10", "minorversion": "0"}}, "partial": {{"start": "0x00000000", "end": "0xFFFFFFFF", "snapshot": []}}, "std": {{"stdin": "", "stdout": "", "stderr": ""}}}}, "sandbox": {{"basic": {{"timeout": 60, "enforce_timeout": "off", "priority": "2", "machine": "", "interaction": "on", "date": "12-12-2000 12:12:00"}}, "advanced": {{"network": "no internet", "file_name": "", "executiondir": "%TEMP%", "sleep_skip": "off", "anti_anti": "on", "serial": "", "procdump": "on", "procmem": "off", "password": "", "call_exports": [], "loader": "rundll32.exe", "arguments": ""}}}}, "platform": {platform}, "mode": "multi-tasking"}}'
}
            

    response = requests.post(url, headers=headers, json=config)
    
    if response.status_code == 200:
        print("Request pushed successfully.")
        return 1
    else:
        print("Failed to push request. Error:", response.text)
        return 0

def get_file_paths(folder_path):
    file_paths = []  # Danh sách đường dẫn tệp
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)  # Đường dẫn tệp
            file_paths.append(file_path)
    return file_paths

def get_karton_analysis_result(sha256, token):
    url = f"http://192.168.14.183:3344/api/object/{sha256}/karton"
    headers = {
        "Authorization": f"Bearer {token}"
    }

    # Thay thế {sha256} và {token} trong URL và header
    # url = url.replace("{sha256}", sha256)
    headers["Authorization"] = headers["Authorization"]
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = response.json()
        amas_report = result['analyses']
        # print(result)
        return amas_report
    else:
        print("Error:", response.status_code)
        return None
    
def check_file_uploaded(sha256, token):
    res = get_karton_analysis_result(sha256, token)
    if res:
        print("File has been uploaded")
        return res
    else:
        print("The file has not been uploaded yet")
        return None

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as file:
        # Đọc dữ liệu từ tệp tin theo từng khối để tính mã băm
        for block in iter(lambda: file.read(4096), b''):
            sha256_hash.update(block)
    return sha256_hash.hexdigest()

def save_token(sample_folder):
    login = 'aidev'
    password = 'Ncs@2023'
    file_paths = get_file_paths(sample_folder)
    # file_paths = file_paths[1003:]
    for file_path in file_paths:
        # file_name = os.path.basename(file_path)
        token = get_auth_token(login, password)
        if token:
            print("token: ", token)
            sha256 = calculate_sha256(file_path)
            check = check_file_uploaded(sha256, token)
            if check is None:
                sha256 = None
                # upload to get emul
                sha256 = upload_and_get_sha256(file_path, token)
                if sha256:
                    time.sleep(30)
                    reup = reupload_file(file_path, token, sha256,platform = 2)
                    time.sleep(400)
                    response = get_karton_analysis_result(sha256, token) 
                    if response:
                        amas_dict = {}
                        for res in response:
                            if len(res["amas_report"]) != 0:
                                if len(res["amas_report"]["platform"]) != 0:
                                    if res["amas_report"]["platform"][0] == "emulator":
                                        amas_dict["emulator"] = res["amas_report"]
                                    elif res["amas_report"]["platform"][0] == "sandbox":
                                        amas_dict["sandbox"] = res["amas_report"]
                                    else:
                                        continue
                        response_file_name = sha256 + '.json'
                        response_file_path = os.path.join(report_folder, response_file_name)
                        with open(response_file_path, 'w') as response_file:
                            json.dump(amas_dict, response_file)
            if check is not None:
                response = check
                check_platform = []
                for res in response:
                    if len(res["amas_report"]) != 0:
                        if len(res["amas_report"]["platform"]) != 0:
                            if res["amas_report"]["platform"][0] == "emulator":
                                check_platform.append("emulator")
                            elif res["amas_report"]["platform"][0] == "sandbox":
                                check_platform.append("sandbox")
                        else:
                            continue
                if "emulator" not in check_platform:
                    print("Reup to get emul")
                    reup = reupload_file(file_path, token, sha256, platform = 1)
                    time.sleep(30)
                if "sandbox" not in check_platform:
                    print("Reup to get sandbox")
                    reup = reupload_file(file_path, token, sha256, platform = 2)
                    time.sleep(400)
                response = get_karton_analysis_result(sha256, token) 
                if response:
                    amas_dict = {}
                    for res in response:
                        if len(res["amas_report"]) != 0:
                            if len(res["amas_report"]["platform"]) != 0:
                                if res["amas_report"]["platform"][0] == "emulator":
                                    amas_dict["emulator"] = res["amas_report"]
                                elif res["amas_report"]["platform"][0] == "sandbox":
                                    amas_dict["sandbox"] = res["amas_report"]
                                else:
                                    continue
                response_file_name = sha256 + '.json'
                response_file_path = os.path.join(report_folder, response_file_name)
                with open(response_file_path, 'w') as response_file:
                    json.dump(amas_dict, response_file)
        else:
            continue
  
save_token(sample_folder)