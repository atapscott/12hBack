import requests
import json

API_ENDPOINT = "http://127.0.0.1:5000"


def create_user(username, password):

    data = {'username': username, 'password': password}
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

    r = requests.post(url="{}{}".format(API_ENDPOINT, "/api/users"), data=json.dumps(data), headers=headers)

    print(r.text)


def get_protected_URI(username, password):
    r = requests.get(url="{}{}".format(API_ENDPOINT, "/api/resource"), auth=(username, password))
    print(r)


if __name__ == '__main__':
    create_user('alan', 'password')