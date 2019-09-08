#!/usr/bin/env python
# coding: utf-8

# ripped from: https://www.v13.gr/blog/?p=303


import OpenSSL
from Crypto.Util import asn1

c=OpenSSL.crypto

# This is the certificate to validate
# an OpenSSL.crypto.X509 object
cert=...

# This is the CA certificate to use for validation
# again an OpenSSL.crypto.X509 object
cacert=...

# Get the signing algorithm
algo=cert.get_signature_algorithm()

# Get the ASN1 format of the certificate
cert_asn1=c.dump_certificate(c.FILETYPE_ASN1, cert)

# Decode the certificate
der=asn1.DerSequence()
der.decode(cert_asn1)

# The certificate has three parts:
# - certificate
# - signature algorithm
# - signature
# http://usefulfor.com/nothing/2009/06/10/x509-certificate-basics/
der_cert=der[0]
der_algo=der[1]
der_sig=der[2]

# The signature is a BIT STRING (Type 3)
# Decode that as well
der_sig_in=asn1.DerObject()
der_sig_in.decode(der_sig)

# Get the payload
sig0=der_sig_in.payload

# Do the following to see a validation error for tests
# der_cert=der_cert[:20]+'1'+der_cert[21:]

# First byte is the number of unused bits. This should be 0
# http://msdn.microsoft.com/en-us/library/windows/desktop/bb540792(v=vs.85).aspx
if sig0[0]!='\x00':
    raise Exception('Number of unused bits is strange')

# Now get the signature itself
sig=sig0[1:]

# And verify the certificate
try:
    c.verify(cacert, sig, der_cert, algo)
    print "Certificate looks good"
except OpenSSL.crypto.Error, e:
    print "Sorry. Nope."


