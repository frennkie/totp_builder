# TOTP Builder (totp_builder.py)

## Overview

Create TOTP secrets, encode in Google Authenticator compatible QR Code and send
via S/MIME encrypted e-mail.

### Requirements

* python2
* python-m2crypto
* pyotp
* qrcode

#### Install on Ubuntu

```
apt-get install python2 python-pip python-m2crypto qrcode
pip install pyotp
```

### Usage / Config

Currently no command line options or help are available. Just run the python script:

```
$: ./totp_builder.py
Validate User Data...

Processing Users...

* JohnDoe (jdoe@example.com): 5PVCLVLMR2SSLIHG

Done!
```


Users are currently hardcoded

```
users = [
    ("JohnDoe", "jdoe@example.com", "jdoe_example.com_smime_public.pem"),
]
```

Just copy line and add more users.

**The certificate is expected to be in "PEM" format**

```
 head jdoe_example.com_smime_public.pem
-----BEGIN TRUSTED CERTIFICATE-----
MIIFPzCCAycCAQEwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCQVUxEzARBgNV
BAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0
ZDAeFw0xNzAyMTkxMDEzNTZaFw0xODAyMTkxMDEzNTZaMIGFMQswCQYDVQQGEwJB
[...]
```
