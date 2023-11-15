import requests
import configparser
import json
import ast
import time
config = configparser.ConfigParser()
config.read('config.ini')

report_folder = config.get("path", "report_folder")

# def read_dicts_from_file(file_path):
    

def get_sha256(file_path):
    data = {}
    with open(file_path, 'r') as file:
        file_content = file.read()
        dicts = file_content.split('}{')
        dicts[0] = dicts[0] + '}'
        dicts[-1] = '{' + dicts[-1]
        for d in dicts:
            if d.find('{') == -1:
                d = '{' + d
            if d.find('}') == -1:
                d = d + '}'
            d = json.loads(d)
            for key, value in d.items():
                data[key] = value
    return data
    
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
        amas_report = result['analyses'][0]
        # print(result)
        return amas_report
    else:
        print("Error:", response.status_code)
        return None


def get_amas_log():
    data = get_sha256("tokens.txt")
    data_copy = data.copy()
    for sha256, token in data_copy.items():
        amas_report = get_karton_analysis_result(sha256, token)
        if amas_report:
            print("Write log")
            file_path = f"{report_folder}{sha256}.json" 
            with open(file_path, 'w') as file:
                json.dump(amas_report, file, indent=4)
                # file.write(amas_report)
            # del data[sha256]
            with open("file_done.txt", "a") as file:
                file.write(f"{sha256}\n")
    time.sleep(3*60*60)
    return get_amas_log()

def main():
    

get_amas_log()