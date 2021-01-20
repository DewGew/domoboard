#!/usr/bin/env python

from flask import Flask, g, redirect, url_for, render_template, abort, request, session
from werkzeug.middleware.proxy_fix import ProxyFix
import flask_login
from secrets import compare_digest                                  
from collections import OrderedDict
import argparse, socket, re
import hashlib, json, sys, os, yaml
import modules.api as api
import modules.domoticz as domoticz
import modules.security as security
import modules.webconfig as webconfig
import modules.smarthome as smarthome
from modules.helpers import logger

app = Flask(__name__)
# Needed for use with reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login_form"

users = {}

class User(flask_login.UserMixin):
    pass

@login_manager.user_loader
def user_loader(username):
    if username not in users:
        return

    user = User()
    user.id = username
    user.group = users[username]['group']
    return user
    
@login_manager.request_loader
def request_loader(request):
    if session:
        security.csrfProtect()
        
    config = api.getConfig()
                
    for k, v in config["general_settings"]["users"].items():
        users[k] = v
        
    if config["general_settings"]["domoboard"]["autologon"] == "True":
        users['Auto'] =  {'group': 'user', 'password': 'auto'}

    username = request.form.get('username')
    password = request.form.get('password', '')
    if username not in users:
        return

    user = User()
    user.id = username
    user.group = users[username]['group']
    try:
        user.is_authenticated = compare_digest(password, users[username]['password'])
    except:
        return
    return user

@flask_login.login_required
def generatePage():
    requestedRoute = str(request.url_rule)[1:]
    if request.method == 'POST':
        if request.form.get("save"):       
            webconfig.saveConfig(request.form.get("save", None))
        if request.form.get("backup"):
            webconfig.backupConfig()
    if configValueExists(requestedRoute):
        blockValues = OrderedDict()
        blockArray = []
        configValues = OrderedDict()
        configValues["navbar"] = config["navbar"]["menu"]
        configValues["server_location"] = config["general_settings"]["server"].get("domoticz_url")
        configValues["flask_server_location"] = config["general_settings"]["server"].get("dzgaboard_url")
        configValues["domoboard"] = config["general_settings"]["domoboard"]
        configValues["display_components"] = strToList(config[requestedRoute]["display_components"].get("components"))
        configValues["config"] = config
        for component in configValues["display_components"]:
                match = re.search("^(.+)\[(.+)\]$", component)
                if not match:
                    blockValues[component] = retrieveValue(requestedRoute, component)
                else:
                    blockValues[match.group(1)] = retrieveValue(requestedRoute, component)
                blockArray.append(blockValues)
                blockValues = {}
        return render_template('index.html',
                                configValues = configValues,
                                blockArray = blockArray,
                                _csrf_token = session['_csrf_token'],
                                isAdmin = flask_login.current_user.group == 'admin',
                                currentUser = flask_login.current_user.id,
                                version = webconfig.getVersion(),
                                branch = webconfig.getCurrentBranch(),
                                configfile = configcode,
                                debug = app.debug)
    else:
        abort(404)

@app.route('/')
def index():
    return redirect('dashboard')

@flask_login.login_required
def retrieveValue(page, component):
    dict = OrderedDict()
    try:
        match = re.search("^(.+)\[(.+)\]$", component)
        if not match:
            for k, v in config[page][component].items():
                l = [None]
                l.extend(strToList(v))
                dict[k] = l
        else:
            for sk, sv in config[page][match.group(1)][match.group(2)].items():
                l = [match.group(2)]
                l.extend(strToList(sv))
                dict[sk] = l
    except:
        dict = {}
    return dict
    
@flask_login.login_required
def syslog():
    f = open('logs/dzgaboard.log', 'r+')
    syslog = f.read()
    
    return syslog

def logout_view():
    user_data = flask_login.current_user.id
    session.clear()
    flask_login.logout_user()
    return render_template('logout.html', loggedout = user_data)

@app.route('/login/', methods=['POST', 'GET'])
def login_form():
    allowed = False
    if "autologon_allowed_Ip" in config["general_settings"]["domoboard"]:
        allowed = request.remote_addr in config["general_settings"]["domoboard"]["autologon_allowed_Ip"]
    else:
        allowed = True
    if config["general_settings"]["domoboard"]["autologon"] == "True" and allowed == True:
        username = 'Auto'
        password = users['Auto']['password']
        if username in users and compare_digest(password, users[username]['password']):
            user = User()
            user.id = username
            user.group = users[username]['group']
            flask_login.login_user(user)
            security.generateCsrfToken()
            return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and compare_digest(password, users[username]['password']):
            user = User()
            user.id = username
            user.group = users[username]['group']
            flask_login.login_user(user)
            security.generateCsrfToken()
            return redirect(url_for('dashboard'))
        logger.warning("Login failed from %s", request.remote_addr)
        return render_template('login.html', failed = "Login failed")
    return  render_template('login.html')
    
  
@login_manager.unauthorized_handler
def unauthorized_handler():
    return redirect(url_for('login_form'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
    
@app.errorhandler(405)
def page_not_found(e):
    return render_template('405.html'), 405

def strToList(str):
    if not isinstance(str, list):
        return [str]
    else:
        return str

def configValueExists(value):
    try:
        config[value]
        exists = True
    except:
        exists = False
    return exists

def validateConfigFormat(config):
    requiredSettings = {"general_settings/server": ["domoticz_url", "dzgaboard_url", "user", "password", "secret_key"],
                        "general_settings/domoboard": ["time", "date", "autologon"],
                        "navbar/menu": [None] }
    for sect, fields in requiredSettings.items():
        section = sect.split('/')
        for field in fields:
            try:
                value = config[section[0]][section[1]][field]
            except:
                if field is None:
                        if section[1] not in config[section[0]]:
                            sys.exit("Config section not set: {} with subsection {}".format(section[0], section[1]))
                else:
                    sys.exit("Config field {} not set: section {} with subsection {}".format(field, section[0], section[1]))

def appendDefaultPages(config):
    config['settings'] = {'display_components': {'components': 'settings'}}
    config['log'] =  {'display_components': {'components': 'serverlog'}}
    return config
    
if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", dest="debug", action="store_true",
                  help="Run in debug mode")
    args = parser.parse_args()
       
    configfile = 'config/config.yaml'
    
    try:
        logger.info('Loading configuration...')
        with open(configfile, 'r') as conf:
            unsanitizedConfig = yaml.safe_load(conf)
    except yaml.YAMLError as exc:
        logger.error('ERROR: Please check config.yaml')
    except FileNotFoundError as err:
        logger.error('No config.yaml found...')
        logger.info('Loading default configuration...')
        file = open('config/default_config', 'r+')
        content = file.read()
        logger.info('Create config.yaml...')
        yamlfile = open(configfile, 'w+')
        yamlfile.write(content)
        yamlfile.close()
        file.close()
        with open(configfile, 'r') as conf:
            unsanitizedConfig = yaml.safe_load(conf)
                
    cf = open(configfile, 'r+')
    configcode = cf.read()
    
    config = json.loads(security.sanitizeString(json.dumps(unsanitizedConfig)), object_pairs_hook=OrderedDict)
    watchfiles = [configfile] 
    config = appendDefaultPages(config)
    api.setConfig(config, unsanitizedConfig)
    api.init()
    validateConfigFormat(config)
    domoticz.checkDomoticzStatus(config)
       
    server_location = config["general_settings"]["server"]["domoticz_url"]
    flask_server_location = config["general_settings"]["server"]["dzgaboard_url"]
    logger.info(' Running on %s (Press CTRL+C to quit)' % flask_server_location)

    app.secret_key = config["general_settings"]["server"]["secret_key"]
    app.add_url_rule('/', 'index', index)
    for k, v in config["navbar"]["menu"].items():
        v = strToList(v)
        app.add_url_rule('/' + v[0].lower(), v[0].lower(), generatePage, methods=['GET'])
    app.add_url_rule('/settings', 'settings', generatePage, methods=['GET', 'POST'])
    app.add_url_rule('/log', 'log', generatePage, methods=['GET'])
    app.add_url_rule('/logout/', 'logout', logout_view, methods=['GET'])
    app.add_url_rule('/syslog/', 'syslog', syslog, methods=['GET'])
    app.add_url_rule('/api', 'api', api.gateway, methods=['POST'])
    if 'google_assistant' in config["general_settings"] and config["general_settings"]["google_assistant"]["enabled"] == 'True':
        app.add_url_rule('/googleassistant/sync', 'sync', smarthome.sync, methods=['GET', 'POST'])
        app.add_url_rule('/googleassistant/auth', 'auth', smarthome.auth, methods=['GET', 'POST'])
        app.add_url_rule('/googleassistant/token', 'token', smarthome.token, methods=['POST'])
        app.add_url_rule('/googleassistant/smarthome', 'smarthome', smarthome.fulfillment, methods=['GET', 'POST'])
    try:
        app.run(host=flask_server_location.split(":")[0],port=int(flask_server_location.split(":")[1]), threaded=True, extra_files=watchfiles, debug=args.debug)
    except (socket.error, Exception):
        sys.exit("Error when starting the Flask server: {}".format(Exception))
        