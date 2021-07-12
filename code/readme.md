# Certificate generation and differential test

0. Please first generate a root CA certificate and collect some seed certificates, as described in `../certificate` folder. Copy root CA to `./utils/rootCA.pem`. Copy seeds to `./utils/corpus/` and `./utils/extension_corpus/`.

1. Clear the residue of the last run.

   ```shell
   cd utils
   rm -rf cov/*
   rm -rf stats/*
   rm -rf seeds/*
   rm -rf leaf/*
   rm -rf root/*
   rm -rf unconsis/seeds/*
   rm -rf unconsis/leaf/*
   rm -rf unconsis/root/*
   ```

2. Initialize the coverage transfer graph with the seed certificates.

   ```sh
   cd utils
   cp -rf corpus/* seeds/
   
   # re-sign seed certificates
   cd ../src/
   python3 seeds_process.py
   
   cd ./scripts
   # collect the coverage stastics of seeds
   sh exec.sh
   # initialize the coverage transfer graph
   python3 ../seed_init.py $HOME_DIR/utils/cov
   ```

3. Generate test suites with different strategies.

   ```shell
   # TCERT0 
   python3 modify.py 10000 0 0 # the fist argument is the number of iterations
   
   # TCERT1
   python3 modify.py 10000 1 0
   
   # TCERT2
   python3 modify.py 10000 0 1
   
   # NEZHA
   # 1. Construct the initial GlobalState
   cd src
   rm -rf ../utils/results/*
   sh scripts/verify_openssl_polarssl_gnutls_matrixssl.sh
   sh scripts/simplify_results
   rm -rf ../utils/nss_seeds/*
   rm -rf certdb
   mkdir certdb
   certutil -N -d certdb/ --empty-password
   python3 nss.py split
   python3 nss.py test
   sh scripts/simplify_results_nss
   rm -rf ../utils/result_nss.csv
   python3 nss.py combine
   # 2. Run nezha
   python3 nezha_run.py 10000 # the argument is the number of iterations
   ```

4. Differentially test SSL/TLS implementations with the generated certificates.

   ```shell
   # validate certificates by OpenSSL, Mbed TLS, GnuTLS and MatrixSSL
   cd src
   rm -rf ../utils/results
   mkdir ../utils/results
   sh scripts/verify_openssl_polarssl_gnutls_matrixssl.sh
   
   # simplify the validation results
   sh scripts/simplify_results
   rm -rf ../utils/result.csv
   rm -rf ../utils/result_nss.csv
   python3 result_combine.py $HOME_DIR/utils/ $HOME_DIR/utils/
   python3 analyze_consis.py $HOME_DIR/utils/result.csv
   
   # validate certificates by NSS and simplify results
   rm -rf ../utils/nss_seeds
   mkdir ../utils/nss_seeds
   # create a NSS certificate database
   rm -rf certdb
   mkdir certdb
   certutil -N -d certdb/ --empty-password
   # split the certificate-chain PEM file to several single-certificate PEM files
   python3 nss.py split
   # validate certificates
   python3 nss.py test
   # simplify validation results
   sh scripts/simplify_results_nss
   python3 nss.py combine
   ```

   

