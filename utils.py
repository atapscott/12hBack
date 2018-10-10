import requests
import json
import sys

API_ENDPOINT = "http://127.0.0.1:5000"


def create_user(*args):
    username = args[0][0]
    password = args[0][1]

    data = {'username': username, 'password': password}
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

    r = requests.post(url="{}{}".format(API_ENDPOINT, "/api/user"), data=json.dumps(data), headers=headers)

    return r


def get_key_values(*args):
    username = args[0][0]
    password = args[0][1]
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

    r = requests.get(url="{}{}".format(API_ENDPOINT, "/api/keyvalues"), auth=(username, password), headers=headers)
    return r


def purge_data(*args):
    username = args[0][0]
    password = args[0][1]
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

    r = requests.post(url="{}{}".format(API_ENDPOINT, "/api/purge"), auth=(username, password), headers=headers)
    return r


def update_value(*args):
    username = args[0][0]
    password = args[0][1]
    key = args[0][2]
    value = args[0][3]

    data = {'value': value}
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

    r = requests.put(url="{}{}{}".format(API_ENDPOINT, "/api/keyvalue/", key), data=json.dumps(data), headers=headers,
                     auth=(username, password))

    return r


def get_key_value(*args):
    username = args[0][0]
    password = args[0][1]
    key = args[0][2]

    headers = {'Accept': 'text/plain'}

    r = requests.get(url="{}{}{}".format(API_ENDPOINT, "/api/keyvalue/", key), headers=headers,
                     auth=(username, password))

    return r


if __name__ == '__main__':

    method = eval(sys.argv[1])
    r = method(sys.argv[2:])
    print(r.text)
    pass