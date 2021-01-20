# -*- coding: utf-8 -*-

import os, sys, json
import logging
from flask import request
import random, string

logfile = 'logs/dzgaboard.log'
tokens_directory = "config/tokens/"
DEVICES_DIRECTORY = "config/smarthome_devices/"

sys.path.insert(0, DEVICES_DIRECTORY)

logging.basicConfig(level=logging.INFO)
logFormatter = logging.Formatter('[%(asctime)s %(levelname)s]: %(message)s')
logger = logging.getLogger()
logs = logging.FileHandler(logfile, 'w', 'utf-8')
logs.setFormatter(logFormatter)
logger.addHandler(logs)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Function to load user info #
def get_user(user="all"):
    filename = os.path.join(USERS_DIRECTORY, "users.json")
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
    access_token_file = tokens_directory + access_token
    if os.path.isfile(access_token_file) and os.access(access_token_file, os.R_OK):
        with open(access_token_file, mode='r') as f:
            return f.read()
    else:
        return None

# Function to load device info
def get_device(user_id, device_id):
    filename = DEVICES_DIRECTORY + user_id + "_devices.json"
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
    filename = DEVICES_DIRECTORY + user_id + "_devices.json"
    if os.path.isfile(filename) and os.access(filename, os.R_OK):
        with open(filename, mode='r') as f:
            text = f.read()
            data = json.loads(text)
            return data
    else:
        logger.error("No json file")
        return None

# Random string generator
def random_string(stringLength=8):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for i in range(stringLength))
    
def createJson(user_id):
    filename = DEVICES_DIRECTORY + user_id + "_devices.json"
    if os.path.isfile(filename) and os.access(filename, os.R_OK):
        return
    else:
        dictonary = {
            "Light_123" : {
                "type": "action.devices.types.SWITCH",
                "traits": [
                    "action.devices.traits.OnOff"
                ],
                "name": {
                    "name": "Light_123",
                    "defaultNames": [
                      "Livingroom lamp",
                      "Livingroom light"
                    ],
                    "nicknames": [
                      "TV-room lamp",
                      "TV-room light"
                    ]
                },
                "roomHint": "Livingroom",
                "customData": {
                    "idx": "123",
                }

            },
            "Switch_234" : {
                "type": "action.devices.types.LIGHT",
                "traits": [
                    "action.devices.traits.OnOff"
                ],
                "name": {
                    "name": "Switch_234",
                    "defaultNames": [
                      "Fan switch",
                      "Fan"
                    ],
                    "nicknames": [
                      "Fan",
                      "Air"
                    ]
                },
                "roomHint": "Bedroom",
                "customData": {
                    "idx": "234"
                }

            }
        }
        json_object = json.dumps(dictonary, indent=4)
        with open(filename, mode='w') as f:
            f.write(json_object)
    