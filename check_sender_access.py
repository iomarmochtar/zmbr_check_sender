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
from Milter.utils import parse_addr
from logging.handlers import SysLogHandler
from multiprocessing import Process as Thread, Queue
from ConfigParser import ConfigParser

### VARIABLES BEGIN
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAIN_CONF = os.path.join(BASE_DIR, 'etc/config.ini')

parser = ConfigParser()
parser.read(MAIN_CONF)

S_MAIN = dict(parser.items('main'))
S_DOMAIN_AL = dict(parser.items('domain_alias'))

APP_NAME = S_MAIN['name']
DEBUG = False
if S_MAIN['debug'] == 'true':
	DEBUG = True

# list of domain that will be filtered by this script 
DOMAINS = S_MAIN['domains'].split(';')

EXCEPTION_RE = None
if S_MAIN['exclude_re']:
	EXCEPTION_RE = re.compile(S_MAIN['exclude_re'])

DOMAIN_ALIAS = dict(parser.items('domain_alias'))

LDAP_CONF = dict(parser.items('ldap')) 
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

	def check_from_header(self, from_addr):
		"""
		comparing MAIL FROM: against From: header,
		if From: email is not in list of alias, cannonical then reject it
		"""
		sfilter = LDAP_CONF['search_filter'].format(self.orig_from, from_addr)
		self.logd('Running ldap filter {0}'.format(sfilter))
		result = self.ldp.search_s(LDAP_CONF['base_search'], ldap.SCOPE_SUBTREE, sfilter, ['dn'])
		if result:
			return False

		args = (self.orig_from, from_addr)
		self.log( 'Violation found: %s doesn\'t has any right sending email as %s'%args )
		return 'Client does not have permissions to send as this sender'


	def header(self, name, val):
		name = name.strip().lower()

		if self.orig_from and name == 'from':

			# if FROM: header is using domain alias
			username, domain = parse_addr(val.lower())
			if domain in DOMAIN_ALIAS:
				real_domain = DOMAIN_ALIAS[domain]
				self.logd('FROM: {0} is using domain alias, altering domain to {1}'.format(val, real_domain))
				val = '{0}@{1}'.format(username, real_domain)

			if self.orig_from == val:
				return Milter.CONTINUE
			
			if EXCEPTION_RE and EXCEPTION_RE.search(val):
				self.logd('{0} is match with EXCEPTION regex, continue email to next flow'.format(val))
				return Milter.CONTINUE

			if not self.__init_ldap():
				return self._done(Milter.CONTINUE)
			
			result = self.check_from_header(val)
			if result:
				self.setreply("550", "5.7.1", result)
				return self._done(Milter.REJECT)
		return Milter.CONTINUE

	@Milter.noreply
	def envfrom(self, mailfrom, *str):
		username, domain = parse_addr(mailfrom.lower())
		# check if domain is in checking domain list
		if domain in DOMAINS or domain in DOMAIN_ALIAS: 
			if domain in DOMAIN_ALIAS:
				real_domain = DOMAIN_ALIAS[domain]
				self.logd('MAIL FROM: {0} is using domain alias, altering domain to {1}'.format(mailfrom, real_domain))
				domain = real_domain
			
			self.orig_from = '{0}@{1}'.format(username, domain)
			self.logd('{0} is in domain list {1}'.format(self.orig_from, DOMAINS))
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
