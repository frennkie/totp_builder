#!/usr/bin/env python2
# -*- coding: UTF-8 -*-

# Copyright (c) 2013, Peter Facka
# Copyright (c) 2017, frennkie
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import os
import os.path
import sys
import ldap
import base64
import logging
import smtplib
import datetime
import argparse
import binascii

from M2Crypto import BIO, Rand, SMIME, X509
from M2Crypto.X509 import X509Error
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders

import qrcode
import pyotp


# Versioning
__version_info__ = ('0', '1', '0')
__version__ = '.'.join(__version_info__)


LDAP_URI = 'ldap://ldap.example.com'
SEARCH_BASE = 'o=example,c=com'

QRCODE_FILE="qrcode.png"

OTP_SYSTEM="OTP_AUTH"

SMTP_SERVER="127.0.0.1"
SMTP_FROM="otp-admin@example.com"


def insert_newlines(string, every=64):
    lines = []
    for i in xrange(0, len(string), every):
        lines.append(string[i:i+every])
    return '\n'.join(lines)


def ldap_search(ldap_uri, base, query):
    '''
    Perform an LDAP query.
    '''
    results = []

    try:
        l = ldap.initialize(ldap_uri)
        l.protocol_version = ldap.VERSION3

        search_scope = ldap.SCOPE_SUBTREE
        retrieve_attributes = None

        ldap_result_id = l.search(
            base,
            search_scope,
            query,
            retrieve_attributes
        )
        result_set = []
        while 1:
            result_type, result_data = l.result(ldap_result_id, 0)
            if (result_data == []):
                break
            else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)

        if len(result_set) == 0:
            print('No results found.')
            return

        count = 0
        for i in range(len(result_set)):
            for entry in result_set[i]:
                try:
                    dn = entry[1]
                    mail = entry[1]['mail'][0]
                    uid = entry[1]['uid'][0]
                    cn = entry[1]['cn'][0]

                    # check both userCertificate and userCertificate;binary
                    userCertificateBinary = False
                    if entry[1].get('userCertificate', None):
                        userCertificate = entry[1]['userCertificate'][0]
                    elif entry[1].get('userCertificate;binary', None):
                        userCertificate = entry[1]['userCertificate;binary'][0]
                        userCertificateBinary = True
                    else:
                        print("Warning: No certificate found!")

                    count += 1

                    if userCertificateBinary:
                        pass  # TODO
                    if not userCertificateBinary:
                        pass  # TODO

                    userCertificate_raw = binascii.b2a_base64(userCertificate)
                    userCertificate = "-----BEGIN CERTIFICATE-----\n"
                    userCertificate += insert_newlines(userCertificate_raw).rstrip("\n")
                    userCertificate += "\n-----END CERTIFICATE-----\n"

                    results.append({"dn": dn,
                                    "mail": mail,
                                    "userCertificate": userCertificate,
                                    "uid": uid,
                                    "cn": cn})
                except Exception as err:
                    print("Error: {0}".format(err))
                    raise Exception("Error: {0}".format(err))

    except ldap.LDAPError as e:
        print('LDAPError: %s.' % e)

    finally:
        l.unbind_s()

    return results


def send_mail_ssl(server, sender, to, to_cert, subject, text, files=[], attachments={}, send=False):
    """
    Sends SSL signed mail

    server - mailserver domain name eg. smtp.foo.bar
    sender - content of From field eg. "No Reply" <noreply@foo.bar>
    to - string with email addresses of recipent
    subject - subject of a mail
    text - text of email
    files - list of strings with paths to file to be attached
    attachmets - dict where keys are file names and values are content of files
    to be attached
    send - bool whether message should really be sent
    """

    # create multipart message
    msg = MIMEMultipart()

    # attach message text as first attachment
    msg.attach(MIMEText(text))

    # attach files to be read from file system
    for file in files:
        part = MIMEBase('application', "octet-stream")
        part.set_payload(open(file, "rb").read() )
        Encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"'
                       % os.path.basename(file))
        msg.attach(part)

    # attach filest read from dictionary
    for name in attachments:
        part = MIMEBase('application', "octet-stream")
        part.set_payload(attachments[name])
        Encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"' % name)
        msg.attach(part)

    msg_str = msg.as_string()

    # Make a MemoryBuffer of the message.
    buf = BIO.MemoryBuffer(msg_str)

    # Seed the PRNG.
    Rand.load_file('randpool.dat', -1)

    # Instantiate an SMIME object.
    s = SMIME.SMIME()

    # Load target cert to encrypt to.
    x509 = X509.load_cert_string(to_cert)
    sk = X509.X509_Stack()
    sk.push(x509)
    s.set_x509_stack(sk)

    # Set cipher: 3-key triple-DES in CBC mode.
    s.set_cipher(SMIME.Cipher('des_ede3_cbc'))

    # Encrypt the buffer.
    p7 = s.encrypt(buf)

    # Output p7 in mail-friendly format.
    out = BIO.MemoryBuffer()
    out.write('From: %s\n' % sender)
    out.write('To: %s\n' % to)
    out.write('Subject: %s\n' % subject)

    # append signed message and original message to mail header
    s.write(out, p7)

    # Save the PRNG's state.
    Rand.save_file('randpool.dat')

    # finally send mail
    if send:
        #        print("would have sent")
        smtp = smtplib.SMTP(server)
        smtp.sendmail(sender, to, out.read() )
        smtp.close()
    else:
        print("sending is disabled (use --send)")


def create_and_send_qrcode(user,
                           user_email=None,
                           user_cert=None,
                           system=OTP_SYSTEM,
                           server=SMTP_SERVER,
                           sender=SMTP_FROM,
                           send=False):

    # generate time based OTP secret
    shared_secret = pyotp.random_base32()

    # generate Google Authenticator comaptible URL and encode in QR Code then
    # save QR Code as .png file to disk
    totp = pyotp.TOTP(shared_secret)
    qrcode_text = totp.provisioning_uri("{0}@{1}".format(user, system))
    img = qrcode.make(qrcode_text)
    img.save(QRCODE_FILE)

    # send QR Code .png as attachment to use in S/MIME encrypted mail
    res = send_mail_ssl(server,
                        sender,
                        to=user_email,
                        to_cert=user_cert,
                        subject="QR Code {0}@{1}".format(user, system),
                        text=("Dear UserID {0},\n\nplease find attached the "
                              "QR Code to provision the Google Authenticator "
                              "App for: {1}".format(user, system)),
                        files=[QRCODE_FILE],
                        send=send)

    # securely delete .png file from disk
    # TODO
    try:
        os.system("shred -uf {0}".format(QRCODE_FILE))
    except Exception as err:
        print("Error: {0}".format(err))

    try:
        os.system("srm -f {0}".format(QRCODE_FILE))
    except Exception as err:
        print("Error: {0}".format(err))

    return shared_secret, qrcode_text


def main():

    # set up command line argument parsing
    parser = argparse.ArgumentParser(description="Generate TOTP Tokens and "
                                                 "send to User via S/MIME "
                                                 "encrypted eMail")
    parser.add_argument("-V", "--version",
                        help="print version", action="version",
                        version=__version__)

    parser.add_argument("-v", "--verbose",
                        help="console output verbosity",
                        action="count")

    parser.add_argument("--no-ldap",
                        help="disable fetching S/MIME certificates from LDAP",
                        action="store_true")

    parser.add_argument("--send",
                        help="enable sending message",
                        action="store_true")

    parser.add_argument("--certificate",
                        help="certificate file (needed if LDAP is disabled)",
                        action="store")

    parser.add_argument("mail",
                        help="eMail address",
                        action="store")


    # parse args
    args = parser.parse_args()

    mail = args.mail

    print("Processing eMail address: {0}\n".format(mail))

    if args.no_ldap:

        if not args.certificate:
            raise NotImplementedError("If LDAP is disabled then a "
                                      "certificate file is required!")
        with open(args.certificate, 'r') as f:
            cert = f.read()

        user_dct = {
            "cn": mail,
            "userCertificate": cert
        }


    else:
        if args.certificate:
            raise NotImplementedError("A certificate can not be provided if "
                                      "LDAP is enabled!")
        query = '(mail={0})'.format(mail)
        ldap_result = ldap_search(LDAP_URI, SEARCH_BASE, query)

        if len(ldap_result) == 0:
            print("No result")
            sys.exit(0)
        elif len(ldap_result) == 1:
            user_dct = ldap_result[0]
        else:
            print("Warning: More than one result.. using first!")
            user_dct = ldap_result[1]

    try:
        x509 = X509.load_cert_string(user_dct["userCertificate"])
    except IOError as err:
        raise Exception("Error: Certificate not found: {0}\n"
                        "Msg: {1}".format(user_dct["cn"], err))
    except X509Error as err:
        raise Exception("Error: Certificate problem: {0}\n"
                        "Check format (should be PEM)\n"
                        "openssl x509 -inform DER -in {0}\n"
                        "Msg: {1}".format(user_dct["cn"], err))


    code, uri = create_and_send_qrcode(user=user_dct["cn"],
                                       user_email=mail,
                                       user_cert=user_dct["userCertificate"],
                                       send=args.send)
    print("* {0} ({1}): {2}".format(user_dct["cn"], mail, code))

    print("SQL Statement (if user id is cn)")
    print('update user_preferences set preferences_value = "{0}" where '
          'preferences_key = "UserGoogleAuthenticatorSecretKey" and '
          'user_id = (select id from users where '
          'login = "{1}");'.format(code, user_dct["cn"]))

if __name__ == '__main__':
    main()
