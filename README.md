# TOTP Builder (totp_builder.py)

## Overview

Create TOTP secrets, encode in Google Authenticator compatible QR Code and send
via S/MIME encrypted e-mail.

### Requirements

* python2
* python-m2crypto
* pyotp
* qrcode

* shred (securely delete files)
or
* srm

#### Install on Ubuntu

```
sudo apt-get update
sudo apt-get install -y python2.7 python-pip python-m2crypto python-qrcode python-ldap shred
sudo -H pip2 install pyotp
```

#### Install on CentOS 7

```
sudo yum install -y python2 python-pip m2crypto python-qrcode srm
sudo -H pip2 install pyotp
```

### Usage / Config

Currently no command line options or help are available. Just run the python script:

```
$: ./totp_builder.py --certificate jdoe_example_com_public.pem --no-ldap --send jdoe@example.com
Processing eMail address: example.com

* example.com (example.com): F4UU3QROWF2LHYYK
SQL Statement (if user id is cn)
```

or

```
$: ./totp_builder.py jdoe@example.com
Processing eMail address: jdoe@example.com

Warning: More than one result.. using first!
* Doe John (jdoe@example.com): VYQXC7WJ53JK4K2F
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

### Screenshot

![Thunderbird](/docs/images/thunderbird_screenshot.png)
