#!/usr/bin/env python2.7

# https://medium.com/@richardgirges/authenticating-open-source-dc-os-with-third-party-services-125fa33a5add

import argparse
import jwt
import time
import sys

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

def args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--account", help = "DCOS user account")
    parser.add_argument("-s", "--secret", help="DCOS Cluster's Master Secret. Get it from file /var/lib/dcos/dcos-oauth/auth-token-secret")
    parser.add_argument("-e", "--expires", help="Token expiration in days", default=1)
    parser.add_argument("-H", "--url", help="DCOS Cluster's Master URL")

    a = parser.parse_args()
    return a


if __name__ == "__main__":
    arguments = args()
    try:
        token = gen_token(arguments.account, arguments.expires, arguments.secret)
        if token_is_valid(arguments.url, token):
            print(token)
    except TypeError:
        print("usage: ./get_token.py -H https://dcos-master.com -e 6 -s Master-Key -a user@somewhere.com")
        sys.exit(1)
