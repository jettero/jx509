#!/bin/bash

trap "exit 1" SIGINT

CAS='/C=US/ST=State/L=City/O=Org/OU=Group/CN=CA Root/emailAddress=ca-root@domain.com'
CCS='/C=US/ST=State/L=City/O=Org/OU=Group/CN=Certy Cert/emailAddress=certycert@domain.com'

# do not do this, this is just to bring up some pretend certs for testing
# (seriously do not do use -passin and use a helluvalot more than 1024 bits)
P=unlock
L=1024

O=( -days 3000 -sha256 )
K=( -nodes -new -newkey rsa:$L "${O[@]}" )
S=( x509 -req -CA ca-root.crt -CAkey ca-root.key -CAcreateserial "${O[@]}" )

[ -f ca-root.key   ] || openssl genrsa -aes256 -out ca-root.key -passout "pass:$P" $L
[ -f ca-root.crt   ] || openssl req -x509 "${K[@]}" -keyout   ca-root.key -out ca-root.crt        -subj "$CAS"
[ -f certycert.key ] || openssl req -x509 "${K[@]}" -keyout certycert.key -out certycert.self_crt -subj "$CCS"
[ -f certycert.csr ] || openssl req -new -key certycert.key -out certycert.csr -subj "$CCS"
[ -f certycert.crt ] || openssl "${S[@]}" -in certycert.csr -out certycert.crt

[ -f private.key ] || ln -svf certycert.key private.key
[ -f public.crt  ] || ln -svf certycert.crt public.crt
