#!/bin/bash

# This script generates a locally-trusted keypair for development using mkcert.

mv -f ./dev/tlskey.p12 ./dev/tlskey.p12.bak
mv -f ./dev/pubCert.crt ./dev/pubCert.crt.bak

# Exporting environment variables for key creation
#
export $(cat .env | grep HOSTNAME)
export $(cat .env | grep HOSTNAME_PF)
export $(cat .env | grep HOSTNAME_AM)
export $(cat .env | grep HOSTNAME_PD)
export $(cat .env | grep HOSTNAME_DS)
export $(cat .env | grep HOSTNAME_PLAYGROUND)
export $(cat .env | grep SSL_PWD)

# Create certificate and private key using mkcert
# The public cert (pubCert.crt) is created directly.
# A temporary private key is created, which will be bundled into the .p12 file.
#
mkcert \
  -cert-file dev/pubCert.crt \
  -key-file dev/tlskey-temp.key \
  ${HOSTNAME} ${HOSTNAME_PF} ${HOSTNAME_PD} ${HOSTNAME_AM} ${HOSTNAME_DS} ${HOSTNAME_PLAYGROUND} localhost

# Package key and cert into a PKCS#12 file using openssl
# This creates the final tlskey.p12 file required by Java applications.
#
openssl pkcs12 -export \
  -out dev/tlskey.p12 \
  -inkey dev/tlskey-temp.key \
  -in dev/pubCert.crt \
  -name tlskey \
  -password pass:${SSL_PWD}

# Clean up the temporary private key
#
rm dev/tlskey-temp.key

# Unset all variables
#
unset HOSTNAME
unset HOSTNAME_PF
unset HOSTNAME_AM
unset HOSTNAME_PD
unset HOSTNAME_DS
unset HOSTNAME_PLAYGROUND
unset SSL_PWD