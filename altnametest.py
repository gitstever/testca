#!/bin/env python
import sys
import testca
from testca import DNS, IP, EMAIL
class TestAltNames:

	def __init__(self):
		self.ips = ['127.0.0.1',' 10.0.3.15', '192.168.56.101']
		self.dns_names = ['*.apps.localdomain.com', 'something.localdomain.com', 'localhost.localdomain']
		self.emails = ['test@localdomain.com']
		self.ca = testca.TestCA()

	def make_cert(self, cn, anh):
		dn = '/DC=com/DC=test/O=Org/OU=Org/OU=Org2/OU=People/CN=' + cn
		(key, key_pem, pkey, req) = self.ca.make_csr(dn)
		extension = anh.get_m2crypto_extension()
		cert = self.ca.sign_cert(req, extensions=[extension])
		self.ca.save(key, key_pem, cert)
		print cert.as_text()

	def ip_as_dns_first(self):
		anh = testca.AltNameHelper()
		for ip in self.ips:
			anh.add_dns(ip)
		for dns in self.dns_names:
			anh.add_dns(dns)
		for email in self.emails:
			anh.add_email(email)
		cn = 'badipfirst.localdomain.com'
		self.make_cert(cn, anh)

	def ip_as_dns_after(self):
		anh = testca.AltNameHelper()
		for dns in self.dns_names:
			anh.add_dns(dns)
		for ip in self.ips:
			anh.add_dns(ip)
		for email in self.emails:
			anh.add_email(email)
		cn = 'ipasdnsafter.localdomain.com'
		self.make_cert(cn, anh)

	def dns_then_ip(self):
		anh = testca.AltNameHelper()
		for dns in self.dns_names:
			anh.add_dns(dns)
		for ip in self.ips:
			anh.add_ip(ip)
		for email in self.emails:
			anh.add_email(email)
		cn = 'good.dnsthenip.localdomain.com'
		self.make_cert(cn, anh)

	def dns_only(self):
		anh = testca.AltNameHelper()
		for dns in self.dns_names:
			anh.add_dns(dns)
		cn = 'good.dnsonly.localdomain.com'
		self.make_cert(cn, anh)		

def main():
	tan = TestAltNames()
	tan.ip_as_dns_first()
	tan.ip_as_dns_after()
	tan.dns_then_ip()
	tan.dns_only()
	return 0

if __name__ == '__main__':
	sys.exit(main())
