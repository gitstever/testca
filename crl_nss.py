#!/bin/env python
from __future__ import print_function
import argparse
import nss, nss.nss, nss.io, nss.ssl
import os
import sys

class NssCheckCert(object):
	def parse_der_from_file(self, filename):
		sec_item = nss.nss.read_der_from_file(filename)
		return sec_item

	def parse_crl_from_file(self, filename):
		sec_item = self.parse_der_from_file(filename)
		crl = nss.nss.decode_der_crl(sec_item)
		return crl

	def verify(self, cert):
		print('verify')
		print(cert.verify_now(self.certdb, True, 0, []))

	def __init__(self, crl_filenames=[],cert_filenames=[]):
		dbname = 'testca'
		certdir = os.path.expanduser('~') + os.sep + '.testcanss'
		nss.nss.nss_init(certdir)
		nss.nss.nss_init_read_write(dbname)
		self.certdb = nss.nss.get_default_certdb()
		self.slot = nss.nss.get_internal_key_slot()
		self.crls = []
		self.certs = []
		for filename in crl_filenames:
			self.crls.append(self.parse_crl_from_file(filename))
		for filename in cert_filenames:
			if os.sep in filename:
				handle = filename.split(os.sep)[-1]
				print (handle)
			der = self.parse_der_from_file(filename)
			cert = nss.nss.Certificate(der, self.certdb, perm=True, nickname=handle)
			self.certs.append(cert)
		for crl in self.crls:
			print(crl)
		for cert in self.certs:
			print(self.verify(cert))

	def __del__(self):
		pass
def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--crl', help='crl', nargs='*')
	parser.add_argument('--cert', help='X509 Certificates', nargs='*')
	args = parser.parse_args()
	crl_filenames = []
	cert_filenames = []
	for name in ['Test_Intermediate_CA.crl', 'Test_CA.crl']:
		filename = os.path.expanduser('~') + os.sep + '.testca' + os.sep + name
		if os.path.isfile(filename):
			crl_filenames.append(filename)
	for name in ['a','b','c','d','e','f','localhost.localdomain','Test_CA','Test_Intermediate_CA']:
		filename = os.path.expanduser('~') + os.sep + '.testca' + os.sep + name + '.cer'
		if os.path.isfile(filename):
			cert_filenames.append(filename)
	if args.crl:
		for crl in args.crl:
			if os.path.isfile(crl):
				crl_filenames.append(crl)
	if args.cert:
		for cert in args.cert:
			if os.path.isfile(cert):
				cert_filenames.append(cert)
	ncc = NssCheckCert(crl_filenames=crl_filenames, cert_filenames=cert_filenames)
	return 0

if __name__ == '__main__':
	sys.exit(main())

