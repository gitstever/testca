#!/bin/bash
dir=~/.testca
nssdir=${dir}nss
rm -rf ${dir}
rm -rf ${nssdir}
mkdir ${nssdir}
certutil -N -d ${nssdir} --empty-password
./testca.py -a a b c d e f localhost.localdomain -r 4 >/dev/null 2>&1
c_rehash ${dir}
ls -la ${dir}
for name in a b c d e f localhost.localdomain Test_CA Test_Intermediate_CA
do
	openssl x509 -in ${dir}/${name}.pem -inform PEM -outform DER -out ${dir}/${name}.cer
	certutil -A -d ${nssdir} -n ${name} -i ${dir}/${name}.cer -t ",,"
done

sudo openssl pkcs12 -in ${dir}/localhost.localdomain.p12 -nocerts -out /etc/pki/tls/private/localhost.key -nodes -passin pass:password
sudo chown root:root /etc/pki/tls/private/localhost.key
sudo chmod 640 /etc/pki/tls/private/localhost.key
sudo openssl pkcs12 -in ${dir}/localhost.localdomain.p12 -nokeys -out /etc/pki/tls/certs/localhost.crt -passin pass:password
sudo chown root:root /etc/pki/tls/certs/localhost.crt
sudo chmod 644 /etc/pki/tls/certs/localhost.crt
echo 'SSLCACertificateFile /etc/pki/tls/certs/ca-bundle.crt
SSLVerifyClient require
SSLVerifyDepth 10
SSLUserName SSL_CLIENT_S_DN
SSLCARevocationPath /etc/pki/tls/crls/
SSLProtocol -ALL +TLSv1.2
SSLHonorCipherOrder On 
SSLCipherSuite ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA
SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:!LOW:!MD5:!aNULL:!eNULL:!3DES:!EXP:!PSK:!SRP:!DSS
#SSLFIPS on' > ${dir}/my_ssl.conf
sudo cp -p ${dir}/my_ssl.conf /etc/httpd/conf.d/my_ssl.conf
sudo chown root:root /etc/httpd/conf.d/my_ssl.conf
sudo chmod 644 /etc/httpd/conf.d/my_ssl.conf
sudo rm -f /etc/pki/tls/certs/ca-bundle.crt
sudo yum reinstall -y ca-certificates
sudo chown ${USER} /etc/pki/tls/certs/ca-bundle.crt
cat ${dir}/Test_CA.pem >> /etc/pki/tls/certs/ca-bundle.crt
cat ${dir}/Test_Intermediate_CA.pem >> /etc/pki/tls/certs/ca-bundle.crt
sudo chown root /etc/pki/tls/certs/ca-bundle.crt
sudo rm -rf /etc/pki/tls/crls
if [ ! -d /etc/pki/tls/crls ]
then
	sudo mkdir /etc/pki/tls/crls
	sudo chown ${USER}:root /etc/pki/tls/crls
	chmod 755 /etc/pki/tls/crls
fi
for name in $(ls -1 ${dir} | grep ^.*\.crl\.pem$)
do
	cp -p ${dir}/${name} /etc/pki/tls/crls/${name}
	chmod 644 /etc/pki/tls/crls/${name}
done
sudo c_rehash /etc/pki/tls/crls/ >/dev/null
sudo chown -R root:root /etc/pki/tls/crls
if [ ! -f /var/www/html/index.html ]
then
	echo '<html><head></head><body>Hello</body></html>' > /var/www/html/index.html
	chmod 644 /var/www/html/index.html
fi
sudo service nginx stop
sudo service httpd restart

test_https ()
{
for name in a b c d
do
	for version in sslv2 sslv3 tlsv1
	do
		echo cert $name $version
		openssl pkcs12 -in ${dir}/${name}.p12 -out ${dir}/${name}.all.pem -nodes -passin pass:password >/dev/null 2>&1
		if ! curl -s --${version} --cacert /etc/pki/tls/certs/ca-bundle.crt --cert ${dir}/${name}.all.pem --cert-type PEM --key ${dir}/${name}.all.pem --key-type PEM https://localhost.localdomain/ > /dev/null
		then
			#echo ${version} ${dir}/${name}.all.pem could not query https://localhost.localdomain/
			#echo tail -10 /var/log/httpd/ssl_error_log \| grep revoked \| tail -1
			#tail -10 /var/log/httpd/ssl_error_log | grep revoked | tail -1
			echo curl ${version} ${name} failed
		else
			echo curl ${version} ${name} successful
		fi
	done
	for version in ssl2 ssl3 tls1 tls1_1 tls1_2
	do
		if ! openssl s_client -cert ${dir}/${name}.all.pem -key ${dir}/${name}.all.pem -CAfile /etc/pki/tls/certs/ca-bundle.crt -connect localhost.localdomain:443 >/dev/null 2>&1 </dev/null
		then
			echo s_client ${version} ${name} failed
		else
			echo s_client ${version} ${name} successful
		fi
	done
done
}

test_https

sudo service httpd stop

echo configuring nginx
cat $(dirname $0)/nginx/ssl.conf | sudo tee /etc/nginx/conf.d/ssl.conf
cat $(dirname $0)/nginx/nginx.conf | sudo tee /etc/nginx/nginx.conf
sudo chown root:root /etc/nginx/conf.d/ssl.conf /etc/nginx/nginx.conf
sudo chmod 644 /etc/nginx/conf.d/ssl.conf /etc/nginx/nginx.conf
cat ${dir}/Test_CA.crl.pem ${dir}/Test_Intermediate_CA.crl.pem | sudo tee /etc/nginx/crl.pem
sudo chown root:root /etc/nginx/crl.pem
sudo chmod 644 /etc/nginx/crl.pem
cat ${dir}/Test_CA.pem ${dir}/Test_Intermediate_CA.pem | sudo tee /etc/nginx/ca.pem
sudo chown root:root /etc/nginx/ca.pem
sudo chmod 644 /etc/nginx/ca.pem
sudo cp -p /etc/pki/tls/certs/localhost.crt /etc/nginx/cert.pem
sudo cp -p /etc/pki/tls/private/localhost.key /etc/nginx/cert.key
sudo service nginx start

test_https

sudo service nginx stop
sudo service httpd start

ls -1 ${dir} | grep ^.\.pem$ | xargs -I {} openssl verify -crl_check -CApath ${dir} ${dir}/{}
echo
echo certutil -V -d ${nssdir} -n d -u C
certutil -V -d ${nssdir} -n d -u C
