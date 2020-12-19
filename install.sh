#!/bin/bash

bash create_ca.sh
bash create_mailbox.sh
make test
cd project
mkdir input
mkdir bin
cd ..
cp 00001 project/input
cp 00002 project/input
cp 00003 project/input
cp server project/bin
cp sendmsg project/bin
cp recvmsg project/bin
cp signer.pem project/ca/intermediate/certs
cp cacert.pem project/ca/intermediate/certs
