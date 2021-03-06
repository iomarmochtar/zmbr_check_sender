#!/usr/bin/python

__author__ = ('Imam Omar Mochtar', 'iomarmochtar@gmail.com')

"""
For preventing authenticated user set From: header as other email 
"""

import sys
import os
import time
import re
import logging
import uuid
import ldap
import Milter
from pprint import pprint
from email.utils import parseaddr
from logging.handlers import SysLogHandler
from multiprocessing import Process as Thread, Queue
from ConfigParser import ConfigParser

### VARIABLES BEGIN
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAIN_CONF = os.path.join(BASE_DIR, 'etc/config.ini')

parser = ConfigParser()
parser.read(MAIN_CONF)

S_MAIN = dict(parser.items('main'))
# 

APP_NAME = S_MAIN['name']
DEBUG = False
if S_MAIN['debug'] == 'true':
    DEBUG = True


# Exceptions/Whitelisting
EXCEPTION_RE = None
if S_MAIN['exclude_re']:
    EXCEPTION_RE = re.compile(S_MAIN['exclude_re'])

EXCEPTION_ENVE_RE = None
if S_MAIN['exclude_enve_re']:
    EXCEPTION_ENVE_RE = re.compile(S_MAIN['exclude_enve_re'])


# list of domain that will be filtered by this script 
DOMAINS = S_MAIN['domains'].split(';')

LDAP_CONF = dict(parser.items('ldap')) 
LDAP_CONF['search_attrs'] = LDAP_CONF['search_attrs'].split(';')
LDAP_CONF['ret_attrs'] = ['zimbraId']
LDAP_CONF['ret_attrs'].extend(LDAP_CONF['search_attrs'])
### VARIABLES END

# queue for communicating with logging process in background
logq = Queue(maxsize=4)

class CheckSenderAccess(Milter.Base):

    orig_from = None
    
    def __init__(self):
        self.id = Milter.uniqueID()
        self.start_time = time.time()
        self.check_id = re.search(r'(^\w+)-', str(uuid.uuid1()) ).groups()[0]
        self.logd('Sender access run')

    def __init_ldap(self):
        """
        Initialize ldap connection
        """
        ldap_url = LDAP_CONF['url']
        self.ldp = ldap.initialize(ldap_url)

        self.logd('Connect to ldap using url: {0}'.format(ldap_url))
        try:
            self.ldp.simple_bind_s(
                LDAP_CONF['bind'],
                LDAP_CONF['pwd']
            )
            return True
        except ldap.INVALID_CREDENTIALS:
            self.log('Invalid LDAP credential')
        except ldap.SERVER_DOWN:
            self.log('Cannot contact to ldap server using url %s'%ldap_url)
        return False

    def log(self, msg):
        logq.put((self.check_id, msg))

    def _done(self, ret_code):
        """
        Finish mail transaction
        """
        diff_time = time.time() - self.start_time
        self.log("execution time %.4f s"%diff_time)
        return ret_code

    def logd(self, msg):
        """
        Log if DEBUG set to True
        """
        if not DEBUG:
            return
        self.log(msg)

    def gen_search_filter(self, email):
        """
        Generate ldap search filter
        """
        return '(|{0})'.format(
            ''.join( [ '({0}={1})'.format(attr, email) for attr in LDAP_CONF['search_attrs']])
        )

    def populate_emails(self, ldap_result):
        """
        Get all allowed emails based on ldap search
        """
        result = [None, []]
        if not ldap_result:
            return result

        # should not more thatn 1 result data
        if len(ldap_result) > 1:
            self.log('warning: Got to result from ldap search')
            return result

        for key, data in ldap_result[0][1].items():
            if key == 'zimbraId':
                result[0] = data[0]
                continue
            result[1].extend(data)

        return result

    def check_from_header(self, from_addr):
        """
        comparing MAIL FROM: against From: header,
        if From: email is not in list of alias, cannonical then reject it
        """
        
        s_filter = self.gen_search_filter(self.orig_from)
        self.logd('Running ldap filter {0}'.format(s_filter))
        result = self.ldp.search_s(LDAP_CONF['base_search'], ldap.SCOPE_SUBTREE, s_filter, LDAP_CONF['ret_attrs'])
        zimbra_id, mails = self.populate_emails(result)	
        # if email in FROM: header are listed in allowed list
        if from_addr in mails:
            return True

        if zimbra_id and S_MAIN['check_sendas_dist'] == 'true':
            s_filter = '(&(mail={0})(objectClass=zimbraDistributionList)(zimbraACE={1} usr sendAsDistList))'.format(
                from_addr, zimbra_id
            )
            self.logd('Checking for distribution list is enabled, running search filter {0}'.format(s_filter))
            result = self.ldp.search_s(LDAP_CONF['base_search'], ldap.SCOPE_SUBTREE, s_filter, ['dn'])
            if result:
                self.logd('{0} can send as distribution list {1}, allowing mail'.format(self.orig_from, from_addr))
                return True

        self.log( 'Violation found: {0} doesn\'t has any right sending email as {1}'.format(self.orig_from, from_addr) )
        self.setreply("550", "5.7.1", S_MAIN['warn_msg'] )
        return False


    def header(self, name, val):
        name = name.strip().lower()

        if self.orig_from and name == 'from':
            name, from_addr = parseaddr(val.lower())

            # if no email then ignore it
            if not from_addr:
                return Milter.CONTINUE
            # if already same then ignore it
            elif self.orig_from == from_addr:
                return Milter.CONTINUE

            # check if domain header is in checking domain list
            splt = from_addr.split('@')
            if len(splt) != 2:
                return Milter.CONTINUE

            if splt[1] not in DOMAINS: 
                return Milter.CONTINUE

            self.logd('{0} is in domain list ({1})'.format(from_addr, DOMAINS))

            if EXCEPTION_ENVE_RE and EXCEPTION_ENVE_RE.search(from_addr):
                self.logd('{0} is match with EXCEPTION Envelop FROM regex, continue email to next flow'.format(from_addr))
                return self._done(Milter.CONTINUE)

            if not self.__init_ldap():
                return self._done(Milter.CONTINUE)
            
            if not self.check_from_header(from_addr):
                return self._done(Milter.REJECT)

            return self._done(Milter.CONTINUE)

        return Milter.CONTINUE

    @Milter.noreply
    def envfrom(self, mailfrom, *str):
        name, mailfrom = parseaddr(mailfrom.lower())
        if EXCEPTION_RE and EXCEPTION_RE.search(mailfrom):
            self.logd('{0} is match with EXCEPTION regex, ignoring'.format(mailfrom))
            mailfrom = None
        self.orig_from = mailfrom
        return Milter.CONTINUE

def background_logger():

    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.DEBUG)
    handler = SysLogHandler(
        address='/dev/log',
        facility=SysLogHandler.LOG_MAIL
    )

    handler.setFormatter(logging.Formatter('%(name)s: %(message)s'))
    logger.addHandler(handler)

    while True:
        try:
            t = logq.get()
        except KeyboardInterrupt:
            break

        if not t: 
            break
        check_id, msg = t
        msg = "check_id=%s %s"%(check_id, msg)
        logger.info(msg)

def main():
    fmt = '%Y-%m-%d %H:%M:%S'
    print( "{0} milter running on port {1}".format(time.strftime(fmt), S_MAIN['listen_port']))
    # Handle log printing in the background
    bt = Thread(target=background_logger)
    bt.start()

    socketname = 'inet:{0}'.format(S_MAIN['listen_port'])
    timeout = 600
    # Register to have the Milter factory create instances of your class:
    Milter.factory = CheckSenderAccess
    Milter.runmilter("check_sender_access", socketname, timeout)

    # shutting down logging process
    logq.put(None)
    bt.join()
    print("%s milter shutdown" % time.strftime(fmt))

if __name__ == '__main__':
    main()
