import requests
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
        # amas_report = result['analyses'][0]["amas_report"]
        # print(result)
        return result
    else:
        print("Error:", response.status_code)
        return None
    
sha256 = "30e2d946d30d0a88de97301661b47e1ba797d7787cf054231fb35144bef4339b"
token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJsb2dpbiI6ImFpZGV2IiwicGFzc3dvcmRfdmVyIjoiZjExNDFmNDQ1MmNjZGIxMCIsImlkZW50aXR5X3ZlciI6ImJhY2Q3ODdhYzRiM2EwOGEiLCJpYXQiOjE3MDEzMTMzNDQsImF1ZCI6Imh0dHA6Ly8xMjcuMC4wLjEiLCJzY29wZSI6InNlc3Npb24iLCJzdWIiOiJhaWRldiIsImV4cCI6MTcwMTM5OTc0NH0.BxBEGvIdKJYTfEDU2UaItysBijlhAQtcCuciDt4sdR9VRdAreNr4gaW9JUeDNQ_hf8_yhXubqN99P2sQBk-X8Q"
res = get_karton_analysis_result(sha256, token)