# OpenSSL ACVP JSON Parser

This harness is built to ingest and process test vectors provided by NIST as part of the ACVP (Automated Cryptographic Validation Program). 

This tool will process JSON vectors provided by the ACVP servers against the users OpenSSL implementation and generate the test response JSON vectors required by the ACVP protocol.

Vector acquisition and submission to the ACVP server must be handled separately.

This harness is built to support OpenSSL versions 3.x.  

## Supported Algorithms 

| Algorithm | Modes |
|---------|---------|
| AES | CFB(-1,-8,-128),CTR,GCM|
| DRBG| ctr-,hash-,hmac-|
| SHA1| |
| SHA2 | 224, 256, 384, 512 |
| SHA3 | 224, 256, 384, 512 |
| DSA | SigGen, SigVer, KeyGen, PQGVer, PQGGen|
| ECDSA| SigGen, SigVer, KeyGen, KeyVer|
| RSA| SigGen, SigVer, KeyGen (B.3.6)|
| KAS | FFC-Component, ECC-Component|
| SafePrimes| KeyGen, KeyVer|
| 3DES| ECB, CBC|

# Build / Install

## Build Requirements

The following libraries will need to be installed to compile this tool.
```
gcc, make, perl, flex, bison, binutils, deltarpm, perl-Digest-SHA, perl-IPC-Cmd, perl-Data-Dumper
```
This package relies on the cJSON library for JSON file management which is included as a submodule.

A FIPS enabled OpenSSL3.0 installation is required for use with this tool.  See [OpenSSL Install](https://github.com/lightshipsec/ls-acvp-harness/blob/main/README.md#openssl-3x-installation) for more information.
```
git clone --recurse-submodules https://github.com/lightshipsec/ls-acvp-harness.git 
```
The code uses internal OpenSSL header files.  You will need to create a symbolic link in the root ls-acvp-harness directory to your openssl source code location:
```
ln -sf /path/to/opensslSRC openssl
```
Point to your fips-enabled openssl_conf file: 
```
export OPENSSL_CONF=/opt/ossl3/ssl/openssl-fips.cnf
```
Compile with `make`

# Usage

Test vectors must first be acquired from ACVP server.
[Check out the examples folder for sample test vectors, responses and capabilities registration files.](examples/)

To process a vector set, simply use -i to provide the test vectors to process and -o to specify the output location:

```./acvpt -i test_vectors.json -o output_vectors.json```

# OpenSSL 3.x Installation

First clone the OpenSSL 3.x repository you will install.  (For example, 3.0.1 below)

`git clone -b openssl-3.0.1 --single-branch https://github.com/openssl/openssl.git openssl`

Then run

```
./config enable-fips shared --prefix=/opt/ossl3 && make && make install && make install_fips

LD_LIBRARY_PATH=/opt/ossl3/lib64 /opt/ossl3/bin/openssl fipsinstall -module /opt/ossl3/lib64/ossl-modules/fips.so -out /opt/ossl3/ssl/fipsmodule.cnf
```

Then you need to generate an OpenSSL .cnf file that you can use to force the use of FIPS mode. Copy the default OpenSSL config file in /opt/ossl3/ssl/openssl.cnf and call it openssl-fips.cnf (in the same location).  The run the following commands to enable the fips module and provider:

```
sed -i "/# .include fipsmodule.cnf/c\\\n.include /opt/ossl3/ssl/fipsmodule.cnf" openssl-fips.cnf && sed -i "/# fips = fips_sect/c\\\nfips = fips_sect\n" openssl-fips.cnf
```

Then point to this file when running 

```
OPENSSL_CONF=/opt/ossl3/ssl/openssl-fips.cnf ./acvpt ...
```

or export OPENSSL_CONF=/opt/ossl3/ssl/openssl-fips.cnf and run as normal.

See the [OpenSSL Manual Fips Entry](https://www.openssl.org/docs/man3.0/man7/fips_module.html) for more information about enabling FIPS in OpenSSL 3.0

# Support

In need of support?  Contact info@lightshipsec.com

# Authors
Greg McLearn 

Jonathan Plata 

