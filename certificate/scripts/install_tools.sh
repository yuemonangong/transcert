#openssl version 1.1.1c
#fix the prefix location
wget https://www.openssl.org/source/old/1.1.1/openssl-1.1.1c.tar.gz
tar zxvf openssl-1.1.1c.tar.gz
cd openssl-1.1.1c
./config --prefix=//  #fix prefix
#to collect coverage
#./config --prefix=()target folder --fprofile-arcs -ftest-coverage
make && make install
#if something goes wrong with the soft link:
# sudo ln -s /prefix_folder/lib/libcrypto.so.1.1  /usr/lib/libcrypto.so.1.1
# sudo ln -s /prefix_folder/lib/libssl.so.1.1  /usr/lib/libssl.so.1.1

#mbedtls(use to be polarssl)
wget https://tls.mbed.org/download/start/mbedtls-2.16.4-apache.tgz
tar xvf mbedtls-2.16.2-apache.tgz
cd mbedtls-2.16.2
make && make check
#collect code coverage
#mkdir mbedtls
#cd mbedtls
#cmake -D CMAKE_BUILD_TYPE=Coverage mbedtls-2.16.2(mbedtls source code filefolder)
#make

#gnutls
apt install m4
apt install lcov
apt-get install libgmp-dev
cd /home
mkdir documents
cd documents

wget http://ftp.gnu.org/gnu/nettle/nettle-3.4.1.tar.gz
tar -xzvf nettle-3.4.1.tar.gz && cd nettle-3.4.1
./configure --enable-shared
make
make install

apt-get install -y libubsan0 libasan1

mkdir gnutls
wget ftp://ftp.gnutls.org/gcrypt/gnutls/v3.6/gnutls-3.6.10.tar.xz
tar -xvJf gnutls-3.6.10.tar.xz && cd gnutls-3.6.10
./configure --prefix=// #please fix the prefix
#collect coverage
#./configure --prefix=// --enable-code-coverage --with-gcov=gcov --with-included-libtasn1 --with-included-unistring -without-p11-kit LDFLAGS=-fprofile-arcs
make && make install

#matrixssl
wget https://github.com/matrixssl/matrixssl/archive/4-2-1-open.tar.gz
tar -zxvf 4-2-1-open.tar.gz
cd matrixssl-4-2-1-open
make

#nss
apt install libnss3-tools
