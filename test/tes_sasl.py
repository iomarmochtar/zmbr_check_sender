#!/usr/bin/python

__author__ = ('Imam Omar Mochtar', 'iomarmochtar@gmail.com')

"""
Script for testing custom FROM: header as authenticate user in zimbra
adjust some variables below with your environment
"""

import smtplib

username = 'user_test@mail.lab'
password = 'test123'

fake_from  = 'admin@mail.lab'
orig_from = username
to_addr = 'omar@mail.lab'

server = '192.168.113.75'

subject = "Testing fake from"
mail_content = "This email originally from %s"%orig_from

mail_header = """Content-Type: text/plain; charset="utf-8"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Subject: %s
From: %s
To: %s

%s
"""%(subject, fake_from, to_addr, mail_content)

server = smtplib.SMTP('%s:587'%server)
server.starttls()
server.login(username,password)
server.sendmail(orig_from, to_addr, mail_header)
server.quit()
