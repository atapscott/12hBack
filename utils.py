import requests
import json

API_ENDPOINT = "http://127.0.0.1:5000"


def create_user(username, password):

    data = {'username': username, 'password': password}
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

    r = requests.post(url="{}{}".format(API_ENDPOINT, "/api/users"), data=json.dumps(data), headers=headers)

    print(r.text)


def get_values(username, password):
    r = requests.get(url="{}{}".format(API_ENDPOINT, "/api/values"), auth=(username, password))
    print(r)

def update_values(username, password, key_values):

    data = {'username': username, 'key_values': key_values}
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

    r = requests.put(url="{}{}".format(API_ENDPOINT, "/api/values"), data=json.dumps(data), headers=headers,
                     auth=(username, password))

    print(r.text)


if __name__ == '__main__':
    # create_user('alan', 'password')
    update_values('alan', 'password', {'k1': 'v1', 'k2': 'v2'})
    # r = get_values('alan', 'password')
    pass