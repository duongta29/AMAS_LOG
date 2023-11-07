import requests

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
    
# login = 'aidev'
# password = 'Ncs@2023'

# token = get_auth_token(login, password)
# if token:
#     print('Token:', token)
    
