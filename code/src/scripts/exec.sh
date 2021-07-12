#! /bin/bash

openssl_instrumented_src="..." #src file for openssl 
openssl_instrumented_bin="..." #openssl command
HOME_DIR="..." #home filefolder
PEM_DIR=$HOME_DIR"utils/seeds/" #seed filefolder contains the pem file
CA_FILE=$HOME_DIR"utils/rootCA.pem" #CA file
COV_INFO_DIR=$HOME_DIR'utils/cov/' #filefolder that contains the cov result of test cases
OPENSSL_ROOT_DIR=$HOME_DIR'utils/root/'
OPENSSL_LEAF_DIR=$HOME_DIR'utils/leaf/'

cd $PEM_DIR
for file in *.pem; do
      lcov -q  --directory $openssl_instrumented_src --zerocounters #--rc lcov_branch_coverage=1
      root_ca_file=$OPENSSL_ROOT_DIR$file
      leaf_file=$OPENSSL_LEAF_DIR$file
      if [ ! -f "$root_ca_file" ];then
      $openssl_instrumented_bin  verify -CAfile $CA_FILE $PEM_DIR$file > /dev/null
      else
      $openssl_instrumented_bin  verify -CAfile $root_ca_file $leaf_file > /dev/null
      fi
            #$openssl_instrumented_bin  verify -CAfile $CA_FILE   $file > /dev/null
            #
      lcov -q --directory $openssl_instrumented_src --capture --output-file  $COV_INFO_DIR${file%.*}'.info' 2>/dev/null #--rc lcov_branch_coverage=1
            #grep -E 'FNDA:[^0]([0-9.]*),.+' $COV_INFO_DIR${file%.*}'.info' >$COV_RESULT_DIR${file%.*}'.txt'
      lcov --summary $COV_INFO_DIR${file%.*}'.info' >$COV_INFO_DIR${file%.*}'.txt' 2>$COV_INFO_DIR${file%.*}'.txt' #summary file
            #echo ${file%.*}
      rm -rf $COV_INFO_DIR${file%.*}'.info'
done
