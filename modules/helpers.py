# -*- coding: utf-8 -*-

import os
import json
import logging
import requests
from flask import request

import random
import string
import config

logfile = 'logs/dzgaboard.log'

logging.basicConfig(level=logging.INFO)
logFormatter = logging.Formatter('[%(asctime)s %(levelname)s]: %(message)s')
logger = logging.getLogger()
logs = logging.FileHandler(logfile, 'w', 'utf-8')
logs.setFormatter(logFormatter)
logger.addHandler(logs)

# log = logging.getLogger('werkzeug')
# log.setLevel(logging.ERROR)

# Function to load user info #
def get_user(user="all"):
    filename = os.path.join(config.USERS_DIRECTORY, "users.json")
    if os.path.isfile(filename) and os.access(filename, os.R_OK):
        with open(filename, mode='r') as f:
            text = f.read()
            data = json.loads(text)
            if "all" == user:
                return data
            else:
                return data[user]
    else:
        logger.warning("users not found")
        return None
        
# Function to retrieve token from header #
def get_token():
    auth = request.headers.get('Authorization')
    parts = auth.split(' ', 2)
    if len(parts) == 2 and parts[0].lower() == 'bearer':
        return parts[1]
    else:
        logger.warning("invalid token: %s", auth)
        return None

# Function to check current token, returns username #
def check_token():
    access_token = get_token()
    access_token_file = os.path.join(config.TOKENS_DIRECTORY, access_token)
    if os.path.isfile(access_token_file) and os.access(access_token_file, os.R_OK):
        with open(access_token_file, mode='r') as f:
            return f.read()
    else:
        return None

# Function to load device info
def get_device(user_id, device_id):
    filename = os.path.join(config.DEVICES_DIRECTORY, user_id + "_devices.json")
    if os.path.isfile(filename) and os.access(filename, os.R_OK):
        with open(filename, mode='r') as f:
            text = f.read()
            jdata = json.loads(text)
            data = jdata[device_id]
            data['id'] = device_id
            return data
    else:
        return None
        
# Function to load device info
def get_devices(user_id):
    filename = os.path.join(config.DEVICES_DIRECTORY, user_id + "_devices.json")
    if os.path.isfile(filename) and os.access(filename, os.R_OK):
        with open(filename, mode='r') as f:
            text = f.read()
            data = json.loads(text)
            return data
    else:
        return None

# Random string generator
def random_string(stringLength=8):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for i in range(stringLength))
    