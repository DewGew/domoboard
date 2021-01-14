#!/usr/bin/python
# This file contains the functions used for web based configuration of domoboard

import git, yaml
from modules import api
from modules.helpers import logger
from flask import request

configfile = 'config/config.yaml'


def writeToConfig(idx, page, component, description, extra):
    originalCfg = api.getOriginalConfig()
    section = dict(originalCfg[page][component])
    section[description] = idx
    originalCfg[page][component] = section
       
    file = open(configfile, 'w+')
    file.write(yaml.safe_dump(originalCfg, allow_unicode=True, sort_keys=False))
    file.close()
    
def saveConfig(codeToSave):
    file = open(configfile, 'w+')
    file.write(codeToSave)
    file.close()
    logger.info("Config saved")
            
def backupConfig():
    original = api.getOriginalConfig()
    backup = open('config/config.yaml.bak', 'w+')
    backup.write(yaml.safe_dump(original, allow_unicode=True, sort_keys=False))
    backup.close()
    logger.info("Config backup is saved")

def indexWebConfig(params={}):
    if 'page' in params:
        return api.getConfig()[params['page']]
    else:
        return api.getConfig()

def getVersion():
    f = open('VERSION.md', 'r')
    version = f.read().rstrip()
    f.close()
    return version

def performUpgrade():
    git.cmd.Git('.').pull()
    return "Upgrade completed."

def getCurrentBranch():
    try:
        repo = git.Repo('.')
        branch = repo.active_branch
        return branch.name
    except:
        return "None"
