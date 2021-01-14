#!/bin/bash
# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
set -o errexit

NAME="dzgaboard"
INSTALL_DIR="$(realpath $(dirname ${BASH_SOURCE[0]})/..)"
ROOT_DIR="$(realpath $(dirname ${BASH_SOURCE[0]})/../..)"

if [ ! -d ${INSTALL_DIR} ]; then
	echo ""
	echo " Can't find Dzgaboard folder!"
	echo ""
	exit 1
fi
echo " *--------------------**---------------------*"
echo " Installation for Synology"
echo " ---------------------------------------------"
echo " *Note : Dzgaboard is free"
echo " *for personal use."
echo " ---------------------------------------------"
echo ""
if ! hash python3; then
    echo " Python3 is not installed"
    exit 1
fi
ver=$(python3 -V 2>&1 | sed 's/.* \([0-9]\).\([0-9]\).*/\1\2/')
if [ "$ver" -lt "35" ]; then
    echo " $NAME requires python 3.5 or greater"
	echo ""
    exit 1
fi
echo "Continue?"
echo "(y)es or (N)o?"
read choice
if [ "$choice" = "N" ] || [ "$choice" = "n" ]; then
	echo "User abort installation"
	exit 0
fi
echo ""
echo " Create virtual enviroment..."
echo ""
wget https://bootstrap.pypa.io/get-pip.py
sleep 5
python3 get-pip.py
python3 -m pip install virtualenv
python3 -m virtualenv ${INSTALL_DIR}/env
${INSTALL_DIR}/env/bin/python -m pip install --upgrade pip setuptools wheel
source ${INSTALL_DIR}/env/bin/activate

echo ""
echo " Installing python packages..."
echo ""
pip3 install -r ${INSTALL_DIR}/requirements.txt

echo ""
echo " Create dzga daemon file"
echo ""
cp ${INSTALL_DIR}/scripts/systemd/dzgaboard_synology dzgaboard-daemon
sudo chmod 755 dzgaboard-daemon
sudo ${ROOT_DIR}/dzgaboard-daemon restart

echo ""
echo "  Login to Dzgaboard Server UI at: http://ip.address:8181"
echo "  Default username is admin and default password is admin"
echo "  or"
echo "  Goto Dzgaboard/config folder and Edit config.yaml and then"
echo "  restart dzgaboard server"
echo ""
echo "  == Useful commands =="
echo "  Start server with command 'sudo ${ROOT_DIR}/dzgaboard-daemon start'"
echo "  Stop server with command 'sudo ${ROOT_DIR}/dzgaboard-daemon stop'"
echo "  Restart server with command 'sudo ${ROOT_DIR}/dzgaboard-daemon restart'"
echo "  Check server status with command 'sudo ${ROOT_DIR}/dzgaboard-daemon status'"
echo ""
