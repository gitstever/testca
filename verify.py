#!/bin/env python
from __future__ import print_function
import argparse
import hacktestca
import M2Crypto.ASN1
import M2Crypto.EVP
import M2Crypto.m2
import M2Crypto.RSA
import M2Crypto.X509
import OpenSSL.crypto
from OpenSSL import SSL
import os
import sys

class Verify(object):

	def m2crypto_x509_to_openssl_x509(self, cert):
		openssl_x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert.as_pem())
		return openssl_x509

	def m2crypto_key_to_openssl_key(self, key):
		openssl_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key.as_pem(cipher=None))
		return openssl_key

	def cn_from_req_or_x509(self, cert):
		result = None
		subject = cert.get_subject()
		subject_text = subject.as_text()
		if '=' in subject_text:
			result = subject_text.split('=')[-1]
		return result

	def get_filename_from_x509(self, x509):
		cn = self.cn_from_req_or_x509(x509)
		filename = self.dir + os.sep + cn.replace(' ', '_')
		return filename

	def gen_rsa(self, bits):
		key = M2Crypto.RSA.gen_key(bits, M2Crypto.m2.RSA_F4)
		return key

	def get_pkey(self, rsa_key):
		pkey = M2Crypto.EVP.PKey()
		pkey.assign_rsa(rsa_key)
		return pkey

	def make_csr(self, dn, bits=2048, digest='sha1',ca=False):
		key = self.gen_rsa(bits)
		key_pem = key.as_pem(cipher=None)
		pkey = self.get_pkey(key)
		req = M2Crypto.X509.Request()
		req.set_version(2)
		req.set_pubkey(pkey)
		subject = req.get_subject()
		if '/' in dn:
			for section in dn.split('/'):
				if section and len(section) > 0:
					name_value = section.split('=')
					subject.add_entry_by_txt(name_value[0], M2Crypto.ASN1.MBSTRING_ASC, name_value[1], -1, -1, 0)
		if ca:
			extension_stack = M2Crypto.X509.X509_Extension_Stack()
			ext = M2Crypto.X509.new_extension('basicConstraints','CA:TRUE')
			ext.set_critical(1)
			extension_stack.push(ext)
			req.add_extensions(extension_stack)
		req.sign(pkey, digest)
		return (key, key_pem, pkey, req)

	def revoke(self, ca_cert, ca_key, serial_number, reason=b'unspecified'):
		dummy_cert = OpenSSL.crypto.X509()
		dummy_cert.gmtime_adj_notAfter(0)
		not_after = dummy_cert.get_notAfter()
		days = 60
		filename = self.get_filename_from_x509(ca_cert) + '.crl.pem'
		if os.path.isfile(filename):
			with open(filename, 'r') as file:
				crl_pem = file.read()
			crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, crl_pem)
		else:
			crl = OpenSSL.crypto.CRL()
		if serial_number:
			revoked = OpenSSL.crypto.Revoked()
			revoked.set_serial(serial_number)
			revoked.set_reason(reason)
			revoked.set_rev_date(not_after)
			crl.add_revoked(revoked)
		openssl_ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, ca_cert.as_pem())
		openssl_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, ca_key.as_pem(cipher=None))
		crl_pem = crl.export(openssl_ca_cert, openssl_key, OpenSSL.crypto.FILETYPE_PEM, days)
		with open(filename, 'w') as file:
			file.write(crl_pem)


	def create_p12(self, cert, key, ca_certs, password):
		p12 = OpenSSL.crypto.PKCS12()
		p12.set_certificate(self.m2crypto_x509_to_openssl_x509(cert))
		openssl_ca_certs = []
		for ca_cert in ca_certs:
			openssl_ca_certs.append(self.m2crypto_x509_to_openssl_x509(ca_cert))
		p12.set_ca_certificates(openssl_ca_certs)
		p12.set_privatekey(self.m2crypto_key_to_openssl_key(key))
		content = p12.export(password)
		filename = self.get_filename_from_x509(cert)
		with open(filename + '.p12', 'w') as file:
			file.write(content)

	def get_next_serial(self, issuer_cert):
		num = 1
		filename = self.get_filename_from_x509(issuer_cert) + '.index'
		if os.path.isfile(filename):
			with open(filename, 'r') as file:
				content = file.read()
				num  = int(content)
		with open(filename, 'w') as file:
			file.write(str(num + 1))
		return num
			

	def sign_cert(self, req, pkey=None, issuer=None, days=365, digest='sha1',ca=False,pathlen=1):
		if not pkey:
			if self.pkey:
				pkey = self.pkey
		cert = M2Crypto.X509.X509()
		cert.set_version(2)
		cert.set_subject(req.get_subject())
		if not issuer:
			cert.set_issuer(req.get_subject())
			issuer = cert
		else:
			cert.set_issuer(issuer.get_subject())
		cert.set_serial_number(self.get_next_serial(issuer))
		cert.set_pubkey(req.get_pubkey())
		not_before = M2Crypto.m2.x509_get_not_before(cert.x509)
		not_after = M2Crypto.m2.x509_get_not_after(cert.x509)
		M2Crypto.m2.x509_gmtime_adj(not_before, 0)
		M2Crypto.m2.x509_gmtime_adj(not_after, 60*60*24*days)
		if ca:
			ext = M2Crypto.X509.new_extension('basicConstraints','CA:TRUE,pathlen:' + str(pathlen),critical=1)
			cert.add_ext(ext)
			ext2 = M2Crypto.X509.new_extension('keyUsage', 'digitalSignature,keyEncipherment,keyCertSign,cRLSign',critical=1)
			cert.add_ext(ext2)
		else:
			ext = M2Crypto.X509.new_extension('basicConstraints','CA:FALSE',critical=1)
			cert.add_ext(ext)
			ext2 = M2Crypto.X509.new_extension('keyUsage', 'digitalSignature,keyEncipherment',critical=1)
			cert.add_ext(ext2)
	
		hash = OpenSSL.crypto.X509Extension("subjectKeyIdentifier", False, "hash",subject=OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,cert.as_pem()))
		ext3 = M2Crypto.X509.new_extension('subjectKeyIdentifier', str(hash).replace(':',''))
		cert.add_ext(ext3)
		#ext4 = hacktestca.new_extension('authorityKeyIdentifier', 'keyid,issuer:always', 0, issuer=issuer)
		ext4 = hacktestca.new_extension('authorityKeyIdentifier', 'keyid', 0, issuer=issuer)
		cert.add_ext(ext4)
		cert.sign(pkey, digest)
		return cert

	def old_init(self, dir=os.path.expanduser('~') + os.sep + '.testca', dn='/DC=com/DC=test/O=Org/OU=Org/OU=Org2/CN=Test CA'):
		self.dir = dir
		if os.path.isfile(os.path.dirname(sys.argv[0]) + os.sep + 'randpool.dat'):
			M2Crypto.Rand.load_file(os.path.dirname(sys.argv[0]) + os.sep + 'randpool.dat', -1)
		if not os.path.isdir(dir):
			os.makedirs(dir, mode=0o700)
			if '=' in dn and '/' in dn:
				(key, key_pem, pkey, req) = self.make_csr(dn, ca=True)
				cn = self.cn_from_req_or_x509(req)
				filename = dir + os.sep + cn.replace(' ', '_')
				with open(filename + '.key', 'w') as file:
					file.write(key_pem)
				req_pem = req.as_pem()
				with open(filename + '.csr', 'w') as file:
					file.write(req_pem)
				cert = self.sign_cert(req, pkey=pkey, ca=True,pathlen=1)
				with open(filename + '.pem', 'w') as file:
					file.write(cert.as_pem())
				self.root_ca_cert = cert
				self.root_ca_key = key
				self.root_pkey = pkey
				self.revoke(cert, key, None)
				intermediate_dn = '/DC=com/DC=test/O=Org/OU=Org/OU=Org2/CN=Test Intermediate CA'
				if '=' in dn and '/' in intermediate_dn:
					root_cert = cert
					root_pkey = pkey
					(key, key_pem, pkey, req) = self.make_csr(intermediate_dn, ca=True)
					cn = self.cn_from_req_or_x509(req)
					filename = dir + os.sep + cn.replace(' ', '_')
					with open(filename + '.key', 'w') as file:
						file.write(key_pem)
					req_pem = req.as_pem()
					with open(filename + '.csr', 'w') as file:
						file.write(req_pem)
					cert = self.sign_cert(req, pkey=root_pkey, issuer=root_cert, ca=True,pathlen=0)
					with open(filename + '.pem', 'w') as file:
						file.write(cert.as_pem())
					self.revoke(cert, key, None)
					self.ca_cert = cert
					self.ca_key = key
					self.pkey = pkey
		else:
			self.root_ca_cert =  M2Crypto.X509.load_cert(dir + os.sep + 'Test_CA.pem')
			self.root_ca_key = M2Crypto.RSA.load_key(dir + os.sep + 'Test_CA.key')
			self.root_pkey = self.get_pkey(self.root_ca_key)
			self.ca_cert = M2Crypto.X509.load_cert(dir + os.sep + 'Test_Intermediate_CA.pem')
			self.ca_key = M2Crypto.RSA.load_key(dir + os.sep + 'Test_Intermediate_CA.key')
			self.pkey = self.get_pkey(self.ca_key)

	def __init__(self, args=None):
		context = SSL.Context(SSL.TLSv1_2_METHOD)
		context.set_mode(SSL.
		if args:
			if args.ca_file:
				for file in args.ca_file:
					context.load_verify_locations(file, capath=None)
			if args.ca_path:
				for path in args.ca_path:
					context.load_verify_locations(None, capath=path)
			if args.certs:
				for cert in args.certs:
					print(cert)
		
					
if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('--ca_file', help='CAfile',	nargs='*')
	parser.add_argument('--ca_path', help='CApath', nargs='*')
	parser.add_argument('--certs', help='Certs',nargs='*')
	args = parser.parse_args()
	verify = Verify(args=args)
	
