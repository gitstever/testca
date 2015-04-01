#!/bin/bash
dir=~/.testca
c_rehash ${dir}
ls -1 ${dir} | grep ^.*\.pem$ | grep -v ^.*\.crl.pem$ | xargs -I {} openssl verify -crl_check -CApath ${dir} ${dir}/{}
