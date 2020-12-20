#!/bin/bash

mkdir -p ~/.config/firejail
cp /etc/firejail/default.profile ~/.config/firejail/sendmsg.profile
echo "blacklist ${HOME}/Lee-Wang/project/ca/certs" >> ~/.config/firejail/sendmsg.profile
echo "blacklist ${HOME}/Lee-Wang/project/ca/crl" >> ~/.config/firejail/sendmsg.profile
echo "blacklist ${HOME}/Lee-Wang/project/ca/index.txt" >> ~/.config/firejail/sendmsg.profile
echo "blacklist ${HOME}/Lee-Wang/project/ca/newcerts" >> ~/.config/firejail/sendmsg.profile
echo "blacklist ${HOME}/Lee-Wang/project/ca/private" >> ~/.config/firejail/sendmsg.profile
echo "blacklist ${HOME}/Lee-Wang/project/ca/serial"  >> ~/.config/firejail/sendmsg.profile
cp ~/.config/firejail/sendmsg.profile ~/.config/firejail/recvmsg.profile

