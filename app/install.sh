#!/bin/bash

bash create_ca.sh
bash create_mailbox.sh
make test
cd project
mkdir input
mkdir bin
cd ..
mv 00001 project/input
mv 00002 project/input
mv 00003 project/input
mv 00004 project/input
mv server project/bin
mv sendmsg project/bin
mv recvmsg project/bin
mv signer.pem project/ca/intermediate/certs
mv cacert.pem project/ca/intermediate/certs
bash sandbox.sh
