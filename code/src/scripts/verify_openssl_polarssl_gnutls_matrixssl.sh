#! /bin/bash

#modify the home folder/ca_file/result_dir ...
HOME_DIR=""
ca_file=$HOME_DIR""
result_dir=$HOME_DIR""
root_openssl_dir=$HOME_DIR""#folder including openssl root certificates
leaf_openssl_dir=$HOME_DIR"" #folder including openssl leaf certificates
openssl_instrument=".../openssl" #openssl command 
polarssl_instrument= ".../programs/x509/cert_app"#polarssl command
gnutls_instrument="../certtool"#gnutls command
matrixssl_instrument="../matrixssl/test/certValidate" #matrixssl command 
PEM_dir=$HOME_DIR""#folder including the whole certificates 
cd $PEM_dir 



for file in *.pem; do
   result_file=$result_dir${file%.*}".txt" 
   echo '-----START VERIFYING '$file >>$result_file
   root_ca_file=$root_openssl_dir$file
   leaf_file=$leaf_openssl_dir$file
   if [ ! -f "$root_ca_file" ]; then
        $openssl_instrument verify -verbose -CAfile $ca_file $file >>$result_file 2>>$result_file
   else
        $openssl_instrument verify -verbose -CAfile $root_ca_file $leaf_file >>$result_file 2>>$result_file
   fi
   echo '-----END VERIFYING '$file>>$result_file
   echo ' '>>$result_file
done
echo "---complete openssl verification"

for file in *.pem; do
   result_file=$result_dir${file%.*}"_polarssl.txt"
   echo '-----START VERIFYING '$file >>$result_file
   $polarssl_instrument mode='file' filename=$file  ca_file=$ca_file >>$result_file 2>>$result_file
   echo '-----END VERIFYING '$file>>$result_file
   echo ' '>>$result_file
done
echo "---complete polarssl verification"


for file in *.pem; do
   result_file=$result_dir${file%.*}"_gnutls.txt"
   echo '-----START VERIFYING '$file >>$result_file
   $gnutls_instrument --verify --load-ca-certificate=$ca_file <$file >>$result_file 2>>$result_file
   echo '-----END VERIFYING '$file>>$result_file
   echo ' '>>$result_file
done
echo "---complete gnutls verification"



for file in *.pem; do
   result_file=$result_dir${file%.*}"_gnutls.txt"
   echo '-----START VERIFYING '$file >>$result_file
   $matrixssl_instrument -c $ca_file $file >>$result_file 2>>$result_file
   echo '-----END VERIFYING '$file>>$result_file
   echo ' '>>$result_file
done
echo "---complete matrixssl verification"

