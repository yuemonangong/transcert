#! /bin/bash

openssl_instrumented_src="..." #src file for openssl 
openssl_instrumented_bin="..." #openssl command
HOME_DIR="..." #home filefolder
PEM_DIR=$HOME_DIR"utils/seeds/" #seed filefolder contains the pem file
CA_FILE=$HOME_DIR"utils/rootCA.pem" #CA file
COV_INFO_DIR=$HOME_DIR'utils/' #filefolder that contains the cov result of test cases
OPENSSL_ROOT_DIR=$HOME_DIR'utils/root/'
OPENSSL_LEAF_DIR=$HOME_DIR'utils/leaf/'

lcov -q  --directory $openssl_instrumented_src --zerocounters #--rc lcov_branch_coverage=1
cd $PEM_DIR
for file in *.pem; do
      root_ca_file=$OPENSSL_ROOT_DIR$file
      leaf_file=$OPENSSL_LEAF_DIR$file
      if [ ! -f "$root_ca_file" ];then
      $openssl_instrumented_bin  verify -CAfile $CA_FILE $PEM_DIR$file > /dev/null
      else
      $openssl_instrumented_bin  verify -CAfile $root_ca_file $leaf_file > /dev/null
      fi
done
lcov -q --directory $openssl_instrumented_src --capture --output-file  $COV_INFO_DIR'acc_cov.info' 2>/dev/null #--rc lcov_branch_coverage=1
lcov --summary $COV_INFO_DIR'acc_cov.info' >$COV_INFO_DIR'acc_cov.txt' 2>$COV_INFO_DIR'acc_cov.txt' #summary file
rm -rf $COV_INFO_DIR'acc_cov.info'
