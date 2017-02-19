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
import base64
import smtplib
import datetime

from M2Crypto import BIO, Rand, SMIME, X509
from M2Crypto.X509 import X509Error
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders

import qrcode
import pyotp

QRCODE_FILE="qrcode.png"

OTP_SYSTEM="OTP_AUTH"

SMTP_SERVER="127.0.0.1"
SMTP_FROM="admin@example.com"


def send_mail_ssl(server, sender, to, to_cert, subject, text, files=[], attachments={}):
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
    x509 = X509.load_cert(to_cert)
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

    # finaly send mail
    smtp = smtplib.SMTP(server)
    smtp.sendmail(sender, to, out.read() )
    smtp.close()


def create_and_send_qrcode(user,
                           user_email=None,
                           user_cert=None,
                           system=OTP_SYSTEM,
                           server=SMTP_SERVER,
                           sender=SMTP_FROM):

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
                        files=[QRCODE_FILE])

    # securely delete .png file from disk
    os.system("shred -uf {0}".format(QRCODE_FILE))

    return shared_secret, qrcode_text

def main():

    users = [
        ("JohnDoe", "jdoe@example.com", "jdoe_example.com_smime_public.pem"),
    ]

    print("Validate User Data...\n")
    issues = []
    for user in users:
        try:
            x509 = X509.load_cert(user[2])

        except IOError as err:
            issues.append("Error: Certificate not found: {0}\n"
                          "Msg: {1}".format(user[2], err))
        except X509Error as err:
            issues.append("Error: Certificate problem: {0}\n"
                          "Check format (should be PEM)\n"
                          "openssl x509 -inform DER -in {0}\n"
                          "Msg: {1}".format(user[2], err))

    if issues:
        for issue in issues:
            print(issue)

        print("")
        raise Exception("At least one user has a problem, aborting!")

    print("Processing Users...\n")
    for user in users:
        code, uri = create_and_send_qrcode(user=user[0],
                                           user_email=user[1],
                                           user_cert=user[2])
        print("* {0} ({1}): {2}".format(user[0], user[1], code))

    print("\nDone!")

if __name__ == '__main__':
    main()
