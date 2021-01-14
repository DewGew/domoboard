# -*- coding: utf-8 -*-

import config
import importlib
import urllib
import os
import sys
import json

from time import time
from domoticz import get_domoticz_devices
from helpers import logger, get_user, check_token, get_token, random_string, get_device, get_devices
from reportstate import ReportState
from flask import Flask, redirect, request, render_template, send_from_directory, jsonify
from secrets import compare_digest

# Path to device plugins
sys.path.insert(0, config.DEVICES_DIRECTORY)

report_state = ReportState()


last_code = None
last_code_user = None
last_code_time = None

logger.info("Smarthome has started.")

if report_state.enable_report_state():
    logger.info("Smart-home-key.json found")
    
def statereport(requestId, userID, states):
    """Send a state report to Google."""

    data = {}
    data['requestId'] = requestId
    data['agentUserId'] = userID
    data['payload'] = {}
    data['payload']['devices'] = {}
    data['payload']['devices']['states'] = states 
    
    report_state.call_homegraph_api('state', data) 
           
# OAuth entry point
@app.route('/auth', methods=['GET', 'POST'])
def auth():
    global last_code, last_code_user, last_code_time
    if request.method == 'GET':    
        return  render_template('login.html')
    if request.method == 'POST':
        if ("username" not in  request.form
                or "password" not in  request.form
                or "state" not in request.args
                or "response_type" not in request.args
                or request.args["response_type"] != "code"
                or "client_id" not in request.args
                or request.args["client_id"] != config.CLIENT_ID):
                    logger.warning("invalid auth request")
                    return "Invalid request", 400
    # Check login and password
    username = request.form['username']
    password = request.form['password']
    if username in users and compare_digest(password, users[username]['password']):
        user = User()
        user.id = username
        flask_login.login_user(user)
        
        # Generate random code and remember this user and time
        last_code = random_string(8)
        last_code_user = ( request.form)["username"]
        last_code_time = time()

        params = {'state': request.args['state'], 
                  'code': last_code,
                  'client_id': config.CLIENT_ID}
        logger.info("generated code")
        return redirect(request.args["redirect_uri"] + '?' + urllib.parse.urlencode(params))
    
    if "X-Real-Ip" in request.headers:
        logger.warning("Login failed from %s", request.headers["X-Real-Ip"])
    return  render_template('login.html', login_failed=True)

# OAuth, token request
@app.route('/token', methods=['POST'])
def token():
    global last_code, last_code_user, last_code_time
    if ("client_secret" not in  request.form
        or request.form["client_secret"] != config.CLIENT_SECRET
        or "client_id" not in  request.form
        or request.form["client_id"] != config.CLIENT_ID
        or "code" not in  request.form):
            logger.warning("invalid token request")
            return "Invalid request", 400
    # Check code
    if ( request.form)["code"] != last_code:
        logger.warning("invalid code")
        return "Invalid code", 403
    # Check time
    if  time() - last_code_time > 10:
        logger.warning("code is too old")
        return "Code is too old", 403
    # Generate and save random token with username
    access_token = random_string(32)
    access_token_file = os.path.join(config.TOKENS_DIRECTORY, access_token)
    with open(access_token_file, mode='wb') as f:
        f.write(last_code_user.encode('utf-8'))
    logger.info("access granted")
    # Return token without any expiration time
    return jsonify({'access_token': access_token})
    
# Sync request
@app.route('/sync', methods=['GET', 'POST'])
@flask_login.login_required
def sync():
    if report_state.enable_report_state():
        payload = {"agentUserId": flask_login.current_user.id}
        r = report_state.call_homegraph_api('sync', payload)
    return 'Sync request sent by ' + flask_login.current_user.id
    
# Main URL to interact with Google requests
@app.route('/smarthome', methods=['GET', 'POST'])
def fulfillment():
    # Google will send POST requests only, some it's just placeholder for GET
    if request.method == 'GET':return "Your smarthome is ready."

    # Check token and get username
    user_id = check_token()
    if user_id == None:
        return "Access denied", 403
    r =  request.get_json()
    logger.debug("request: \r\n%s", json.dumps(r, indent=4))
    
    result = {}
    result['requestId'] = r['requestId']
    
    get_domoticz_devices(user_id)
        
    # Let's check inputs array.
    inputs = r['inputs']
    for i in inputs:
        intent = i['intent']
        # Sync intent, need to response with devices list
        if intent == "action.devices.SYNC":
            result['payload'] = {"agentUserId": user_id, "devices": []}
            # Loading user info
            devs = get_devices(user_id)
            # Loading each device available for this user
            for device_id in devs.keys():
                # Loading device info
                device =  get_device(user_id, device_id)
                device['willReportState'] = report_state.enable_report_state()
                device['deviceInfo'] = {
                            "manufacturer": "Domoticz",
                            "model": "1",
                            "hwVersion": "1",
                            "swVersion": "1"
                        }
                result['payload']['devices'].append(device)

        # Query intent, need to response with current device status
        if intent == "action.devices.QUERY":
            result['payload'] = {}
            result['payload']['devices'] = {}
            for device in i['payload']['devices']:
                device_id = device['id']
                custom_data = device.get("customData", None)
                # Load module for this device
                logger.info("-----> %s ", device_id)
                device_module = importlib.import_module('trait')
                # Call query method for this device
                query_method = getattr(device_module, device_id + "_query")
                result['payload']['devices'][device_id] = query_method(custom_data)
                
        # Execute intent, need to execute some action
        if intent == "action.devices.EXECUTE":
            result['payload'] = {}
            result['payload']['commands'] = []
            for command in i['payload']['commands']:
                for device in command['devices']:
                    device_id = device['id']
                    custom_data = device.get("customData", None)
                    # Load module for this device
                    device_module = importlib.import_module('trait')
                    # Call execute method for this device for every execute command
                    action_method = getattr(device_module, device_id + "_action")
                    for e in command['execution']:
                        command = e['command']
                        params = e.get("params", None)
                        action_result = action_method(custom_data, command, params)
                        action_result['ids'] = [device_id]
                        result['payload']['commands'].append(action_result)
                        if report_state.enable_report_state():
                            data = {}
                            data[device_id] = action_result['states']
                            statereport(result['requestId'], user_id, data)
        
        # Disconnect intent, need to revoke token
        if intent == "action.devices.DISCONNECT":
            access_token = get_token()
            access_token_file = os.path.join(config.TOKENS_DIRECTORY, access_token)
            if os.path.isfile(access_token_file) and os.access(access_token_file, os.R_OK):
                os.remove(access_token_file)
                logger.debug("token %s revoked", access_token)
            return {}
    
    logger.debug("response: \r\n%s", json.dumps(result, indent=4))
            
    return jsonify(result)

