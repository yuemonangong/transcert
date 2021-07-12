#! /bin/bash

openssl_instrumented_src=''
openssl_instrumented_bin='/bin/openssl'#fix location

CA_FILE=""#pem format fix location
COV_INFO_DIR=''#save cov info
COV_RESULT_DIR=''#save cov result info
root_ca_file=''
leaf_file=''



lcovroo -q  --directory $openssl_instrumented_src --zerocounters #--rc lcov_branch_coverage=1
if [ ! -f "$root_ca_file" ];then
    $openssl_instrumented_bin  verify -CAfile $CA_FILE $file > /dev/null
else
    $openssl_instrumented_bin  verify -CAfile $root_ca_file $leaf_file > /dev/null
fi
      #$openssl_instrumented_bin  verify -CAfile $CA_FILE   $file > /dev/null
lcov -q --directory $openssl_instrumented_src --capture --output-file  $COV_INFO_DIR${file%.*}'.info' 2>/dev/null #--rc lcov_branch_coverage=1
###to extract FNDA data
#grep -E 'FNDA:[^0]([0-9.]*),.+' $COV_INFO_DIR${file%.*}'.info' >$COV_RESULT_DIR${file%.*}'.txt'
lcov --summary $COV_INFO_DIR${file%.*}'.info' >$COV_RESULT_DIR${file%.*}'.txt' 2>$COV_RESULT_DIR${file%.*}'.txt' #summary file

