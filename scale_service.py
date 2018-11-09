#!/usr/bin/env python

import argparse
import jwt
import time
import sys
import json

import requests


def gen_token( account, expire, secret):
    master_key = secret
    exp_time = time.time() + (3600 * (int(expire) * 24))
    token = jwt.encode({'exp' : exp_time, 'uid': account}, master_key, algorithm='HS256')
    return token.decode()

def token_is_valid(dcos_url, token):
    headers = {"Authorization" : "token=%s" %(token)}
    url = dcos_url + '/marathon/v2/info'
    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        return True
    else:
        return False

def scale_service(dcos_url, token, service, number_of_instances):
    headers = {"Authorization" : "token=%s" %(token)}
    url = dcos_url + '/marathon/v2/apps/' + service
    force_scale = {'force': 'false'}
    data = {"instances": number_of_instances}

    resp = requests.put(url, data=json.dumps(data), params=force_scale, headers=headers)
    if resp.status_code == 200:
        return True
    else:
        print(resp.content)
        print("[ERROR] Failed to scale service: {0}".format(service))
        return False

def get_current_number_of_instances(dcos_url, token, service):
    headers = {"Authorization" : "token=%s" %(token)}
    url = dcos_url + '/marathon/v2/apps/' + service

    resp = requests.get(url, headers=headers)
    json_data = resp.json()

    return json_data["app"]["tasksRunning"]


def args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--account", required=True, help = "DCOS user account")
    parser.add_argument("-s", "--secret", required=True, help="DCOS Cluster's Master Secret. Get it from file /var/lib/dcos/dcos-oauth/auth-token-secret")
    parser.add_argument("-e", "--expires", help="Token expiration in days", default=1)
    parser.add_argument("-H", "--url", required=True, help="DCOS Cluster's Master URL")
    parser.add_argument("-S", "--service", required=True, help="Service to scale")
    parser.add_argument("-N", "--instances", default=None, help="Number of instances to scale to." )

    a = parser.parse_args()
    return a


if __name__ == "__main__":
    arguments = args()

    exit_code = 0

    token = gen_token(arguments.account, arguments.expires, arguments.secret)
    if not token_is_valid(arguments.url, token):
        sys.exit(1)

    if arguments.instances:
        number_of_instances = int(arguments.instances)
    else:
        number_of_instances = get_current_number_of_instances(arguments.url, token, arguments.service) + 1

    if not scale_service(arguments.url, token, arguments.service, number_of_instances):
        print('[INFO] Failed to scale service "{0}" to {1} instances'.format(arguments.service, number_of_instances))
        sys.exit(1)

    print('[INFO] Successfully scaled service "{0}" to {1} instances'.format(arguments.service, number_of_instances))

    sys.exit(exit_code)
