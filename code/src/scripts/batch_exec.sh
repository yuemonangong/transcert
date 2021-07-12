#! /bin/bash

openssl_instrumented_src="..." #src file for openssl 
openssl_instrumented_bin="..." #openssl command
HOME_DIR="..." #home filefolder
SEED_FILEFOLDER=$HOME_DIR"utils/seeds/" #conf.seed_filefolder
file=$SEED_FILEFOLDER$1 #input argument is filename of testcase (collect cov)
filename=$1
CA_FILE=$HOME_DIR"utils/rootCA.pem" #rootca name
COV_INFO_DIR=$HOME_DIR"utils/cov/" #conf.cov_results_path
OPENSSL_ROOT_DIR=$HOME_DIR"utils/root/"#conf.openssl_root
OPENSSL_LEAF_DIR=$HOME_DIR"utils/leaf/"#conf.openssl_leaf


lcov -q  --directory $openssl_instrumented_src --zerocounters #--rc lcov_branch_coverage=1
root_ca_file=$OPENSSL_ROOT_DIR$filename
leaf_file=$OPENSSL_LEAF_DIR$filename
if [ ! -f "$root_ca_file" ];then
     $openssl_instrumented_bin  verify -CAfile $CA_FILE $file > /dev/null
else
     $openssl_instrumented_bin  verify -CAfile $root_ca_file $leaf_file > /dev/null
fi
      #$openssl_instrumented_bin  verify -CAfile $CA_FILE   $file > /dev/null
      #
lcov -q --directory $openssl_instrumented_src --capture --output-file  $COV_INFO_DIR${filename%.*}'.info' 2>/dev/null #--rc lcov_branch_coverage=1
      #grep -E 'FNDA:[^0]([0-9.]*),.+' $COV_INFO_DIR${file%.*}'.info' >$COV_RESULT_DIR${file%.*}'.txt'
lcov --summary $COV_INFO_DIR${filename%.*}'.info' >$COV_INFO_DIR${filename%.*}'.txt' 2>$COV_INFO_DIR${filename%.*}'.txt' #summary file
      #echo ${file%.*}
rm -rf $COV_INFO_DIR${filename%.*}'.info'

