#!/bin/bash

# password
password=1234

# information for creating certificate request
country=US
state=NY
locality=Manhattan
org=Security_I_Ltd
orgunit=Security_I_Ltd_Certificate_Authority
root_commonname=Security_I_Ltd_Root_CA
email=NA

intermediate_commonname=Security_I_Ltd_Intermediate_CA

server_commonname=www.server.com


# information for creating certificate request
client_country=US
client_state=NY
client_locality=Manhattan
client_org=SEAS
client_orgunit=CS
client_commonname=yw3472
client_email=yw3472@columbia.edu


# root
mkdir project
mkdir project/ca
cd project/ca
mkdir certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial

# copy openssl file 
cd ../../
cp s_openssl.cnf ./project/ca/openssl.cnf

# create the root key
cd project/ca
openssl genrsa -out private/ca.key.pem 4096

chmod 400 private/ca.key.pem

# create the root certificate
openssl req -config openssl.cnf \
      -key private/ca.key.pem \
      -new -x509 -days 7300 -sha256 -extensions v3_ca \
      -out certs/ca.cert.pem \
      -subj "/C=$country/ST=$state/L=$locality/O=$org/OU=$orgunit/CN=$root_commonname/emailAddress=$email"

chmod 444 certs/ca.cert.pem

# verify the root certificate
openssl x509 -noout -text -in certs/ca.cert.pem


# intermediate
mkdir intermediate
cd intermediate
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial

echo 1000 > crlnumber

# copy openssl file 
cd ../../../
cp i_openssl.cnf ./project/ca/intermediate/openssl.cnf

# create the intermediate key
cd project/ca
openssl genrsa -out intermediate/private/intermediate.key.pem 4096

chmod 400 intermediate/private/intermediate.key.pem

# create the intermediate certificate
openssl req -config intermediate/openssl.cnf -new -sha256 \
      -key intermediate/private/intermediate.key.pem \
      -out intermediate/csr/intermediate.csr.pem \
      -subj "/C=$country/ST=$state/L=$locality/O=$org/OU=$orgunit/CN=$intermediate_commonname/emailAddress=$email"


openssl ca -config openssl.cnf -extensions v3_intermediate_ca \
      -days 3650 -notext -md sha256 \
      -in intermediate/csr/intermediate.csr.pem \
      -out intermediate/certs/intermediate.cert.pem \
      -batch

chmod 444 intermediate/certs/intermediate.cert.pem

# verify the intermediate certificate
#openssl x509 -noout -text \
#      -in intermediate/certs/intermediate.cert.pem

openssl verify -CAfile certs/ca.cert.pem \
      intermediate/certs/intermediate.cert.pem

# create the certificate chain file
cat intermediate/certs/intermediate.cert.pem \
      certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem

chmod 444 intermediate/certs/ca-chain.cert.pem


# sign server certificates

# create the key
openssl genrsa -out intermediate/private/www.server.com.key.pem 2048 \

chmod 400 intermediate/private/www.server.com.key.pem

# create a certificate
# generate .csr file from .key
openssl req -config intermediate/openssl.cnf \
      -key intermediate/private/www.server.com.key.pem \
      -new -sha256 -out intermediate/csr/www.server.com.csr.pem \
      -subj "/C=$country/ST=$state/L=$locality/O=$org/OU=$orgunit/CN=$server_commonname/emailAddress=$email"

# generate .cert file from .csr
openssl ca -config intermediate/openssl.cnf \
      -extensions server_cert -days 375 -notext -md sha256 \
      -in intermediate/csr/www.server.com.csr.pem \
      -out intermediate/certs/www.server.com.cert.pem \
      -batch

chmod 444 intermediate/certs/www.server.com.cert.pem

# verify the certificate
#openssl x509 -noout -text \
#      -in intermediate/certs/www.server.com.cert.pem

openssl verify -CAfile intermediate/certs/ca-chain.cert.pem \
      intermediate/certs/www.server.com.cert.pem





# create clieent ca
# -----------------------------------------------

# create a key
openssl genrsa  -out intermediate/private/www.client.com.key.pem 2048

chmod 400 intermediate/private/www.client.com.key.pem

# create a certificate
# generate .csr file from .key
openssl req -config intermediate/openssl.cnf \
      -key intermediate/private/www.client.com.key.pem \
      -new -sha256 -out intermediate/csr/www.client.com.csr.pem \
      -subj "/C=$client_country/ST=$client_state/L=$client_locality/O=$client_org/OU=$client_orgunit/CN=$client_commonname/emailAddress=$client_email"

# generate .cert from .csr
openssl ca -config intermediate/openssl.cnf \
      -extensions usr_cert -days 375 -notext -md sha256 \
      -in intermediate/csr/www.client.com.csr.pem \
      -out intermediate/certs/www.client.com.cert.pem \
      -batch


chmod 444 intermediate/certs/www.client.com.cert.pem

# verify the certificate
#openssl x509 -noout -text \
#      -in intermediate/certs/www.client.com.cert.pem

openssl verify -CAfile intermediate/certs/ca-chain.cert.pem \
      intermediate/certs/www.client.com.cert.pem


input=("addleness" "analects" "annalistic" "anthropomorphologically" "blepharosphincterectomy" "corector" "durwaun" "dysphasia" "encampment" "endoscopic" "exilic" "forfend" "gorbellied" "gushiness" "muermo" "neckar" "outmate" "outroll" "overrich" "philosophicotheological" "pockwood" "polypose" "refluxed" "reinsure" "repine" "scerne" "starshine" "unauthoritativeness" "unminced" "unrosed" "untranquil" "urushinic" "vegetocarbonaceous" "wamara" "whaledom")

counter=1002

for i in ${input[@]}
do
    # echo serial number
    echo $counter > ./intermediate/serial
    ((counter++))

    # create a key
    openssl genrsa -out intermediate/private/www.$i.com.key.pem 2048

    chmod 400 intermediate/private/www.$i.com.key.pem

    # create a certificate
    # generate .csr file from .key
    openssl req -config intermediate/openssl.cnf \
          -key intermediate/private/www.$i.com.key.pem \
          -new -sha256 -out intermediate/csr/www.$i.com.csr.pem \
          -subj "/C=$client_country/ST=$client_state/L=$client_locality/O=$client_org/OU=$client_orgunit/CN=$client_commonname/emailAddress=$i"

    # generate .cert from .csr
    openssl ca -config intermediate/openssl.cnf \
          -extensions usr_cert -days 375 -notext -md sha256 \
          -in intermediate/csr/www.$i.com.csr.pem \
          -out intermediate/certs/www.$i.com.cert.pem \
          -batch


    chmod 444 intermediate/certs/www.$i.com.cert.pem
done



