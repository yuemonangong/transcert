import os
from OpenSSL import crypto
import subprocess
import sys
import franken_conf_parse
import conf
from datetime import datetime,timedelta
import json
import shutil
import mucert_util

import pandas as pd
import numpy

error_encode_count = 0

def split_cert(filename, indir, outdir, cafile):
    incerts = []
    inpath = os.path.join(indir, filename)
    with open(inpath) as f:
        buf = f.read()
        pattern = "-----BEGIN CERTIFICATE-----"
        index = 0
        while True:
            index = buf.find(pattern, index)
            if (index == -1):
                break
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, buf[index:])
            index = index + len(pattern)
            incerts.append(cert)
    with open(cafile) as f:
        buf = f.read()
        cacert = crypto.load_certificate(crypto.FILETYPE_PEM, buf)
    
    with open(cafile) as f:
        buf = f.read()
        cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, buf)

    if len(incerts) == 0:
        print('0 lenth error:', filename)
        return
    if len(incerts) == 1:
        return
   
    pkeys = [] 
    for i in range(len(incerts)):
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 2048)
        pkeys.append(pkey)
    
    for i in range(len(incerts)):
        incerts[i].set_pubkey(pkeys[i])
   
        if (i == len(incerts) - 1): 
            incerts[i].set_issuer(cacert.get_subject())
            incerts[i].sign(cakey, "sha256")
        else:    
            incerts[i].set_issuer(incerts[i + 1].get_subject())
            incerts[i].sign(pkeys[i + 1], "sha256")

    fname,ext = os.path.splitext(filename)
    targetdir = os.path.join(outdir, fname)
    os.mkdir(targetdir)
    for i in range(len(incerts)):
        outpath = os.path.join(targetdir, str(i)+ext)
        with open(outpath, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkeys[i]))
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, incerts[i]))

def split_certs():
    indir = conf.seed_filefolder
    cafile = conf.ca_cert_path
    outdir = conf.HOME_DIR+'utils/nss_seeds/'
    files = os.listdir(indir)
    for f in files:
        try:
            split_cert(f, indir, outdir, cafile)
        except:
            continue

def nss_test_cert(filename, indir, nssindir, outdir, capath):
    fname,ext = os.path.splitext(filename)
    targetdir = os.path.join(nssindir, fname)
    if os.path.exists(targetdir):
        files = os.listdir(targetdir)
        inpathlist = [os.path.join(targetdir, str(f)+'.pem') for f in range(len(files))]
        print(inpathlist)
        outpath = os.path.join(outdir, fname+'_nss.txt')
        os.system("echo '-----START VERIFYING "+filename+"' >>" + outpath)
        os.system('certutil -A -d certdb/ -n root -i ' + capath + ' -t "T,,"' + ' >>' + outpath + ' 2>>' + outpath)
        for idx in range(len(inpathlist)):
            os.system('certutil -A -d certdb/ -n test' + str(len(inpathlist) - 1 - idx) + ' -i ' + inpathlist[len(inpathlist) - 1 - idx] + ' -t ",,"' + ' >>' + outpath + ' 2>>' + outpath)
        # os.system('certutil -V -d certdb/ -n test' + str(len(inpathlist) - 1) + ' -u C' + ' >>' + outpath + ' 2>>' + outpath)
        os.system('certutil -V -d certdb/ -n test' + str(0) + ' -u C' + ' >>' + outpath + ' 2>>' + outpath)
        for idx in range(len(inpathlist)):
            os.system('certutil -D -d certdb/ -n test' + str(idx) + ' >>' + outpath + ' 2>>' + outpath)
        os.system('certutil -D -d certdb/ -n root' + ' >>' + outpath + ' 2>>' + outpath)
        os.system("echo '-----END VERIFYING "+filename+"' >>" + outpath)

    else:
        inpath = os.path.join(indir, filename)
        outpath = os.path.join(outdir, fname+'_nss.txt')
        os.system("echo '-----START VERIFYING "+filename+"' >>" + outpath)
        os.system('certutil -A -d certdb/ -n root -i ' + capath + ' -t "T,,"' + ' >>' + outpath + ' 2>>' + outpath)
        os.system('certutil -A -d certdb/ -n test -i ' + inpath + ' -t ",,"' + ' >>' + outpath + ' 2>>' + outpath)
        os.system('certutil -V -d certdb/ -n test -u C' + ' >>' + outpath + ' 2>>' + outpath)
        os.system('certutil -D -d certdb/ -n test' + ' >>' + outpath + ' 2>>' + outpath)
        os.system('certutil -D -d certdb/ -n root' + ' >>' + outpath + ' 2>>' + outpath)
        os.system("echo '-----END VERIFYING "+filename+"' >>" + outpath)

def nss_test_certs():
    indir = conf.seed_filefolder
    cafile = conf.ca_cert_path
    nssindir = conf.HOME_DIR+'utils/nss_seeds/'
    outdir = conf.test_results_path
    files = os.listdir(indir)
    for f in files:
        nss_test_cert(f, indir, nssindir, outdir, cafile)


def nss_reason_extract(line):
    content = line.lstrip('-----')
    l_content = content.split('-----')
    reason = " "
    for i in range(1,len(l_content)):
        reason += l_content[i].lstrip("reject for")
        reason += '\n'
    return reason

def nss_txt_table(filepath,mode):
    df = pd.DataFrame()
    with open(filepath,'r') as f:
        for line in f.readlines():
            # line = line.decode('utf-8')
            ca_name = line.split('-----')[1].lstrip('START VERIFYING ').rstrip('.pem')
            if line.find('reject') != -1:
                accept_bool = 'F'
                r_reason = nss_reason_extract(line)
            elif line.find('accept') != -1:
                accept_bool = 'T'
                r_reason='None'
            else:
                accept_bool = 'X'
                r_reason = 'None'
            #state = file_cov[str(ca_name)]
            insert_line = pd.DataFrame([ca_name,accept_bool,r_reason]).T
            df = df.append(insert_line)
    if mode =='0':
         df.columns = ['CA','openssl_acc','openssl_reason'] #remove state due to partial missing info of cov
    elif mode =='1':
         df.columns = ['CA','polarssl_acc', 'polarssl_reason']
    elif mode =='2':
         df.columns = ['CA','gnutls_acc', 'gnutls_reason']#remove state
    elif mode =='3':
         df.columns = ['CA','matrixssl_acc', 'matrixssl_reason']#remove state
    elif mode == '4':
         df.columns = ['CA','nss_acc', 'nss_reason']#remove state
    return df

def nss_result_merge(s_result_folder,result_path):
    gnutls = nss_txt_table(os.path.join(s_result_folder, 's_gnutls.txt'), mode='2')
    openssl = nss_txt_table(os.path.join(s_result_folder, 's_openssl.txt'), mode='0')
    polarssl = nss_txt_table(os.path.join(s_result_folder, 's_polarssl.txt'), mode='1')
    matrixssl = nss_txt_table(os.path.join(s_result_folder, 's_matrixssl.txt'), mode='3')
    nss = nss_txt_table(os.path.join(s_result_folder, 's_nss.txt'), mode='4')
    print(gnutls.shape)
    print(openssl.shape)
    print(polarssl.shape)
    print(matrixssl.shape)
    print(nss.shape)
    df = pd.merge(openssl, polarssl, on=['CA'])#remove state keys
    # df.columns= ['CA','openssl','polarssl']
    openssl_ca = list(df['CA'].values)
    df2 = pd.merge(df, gnutls, on=['CA'])#remove state keys
    df3 = pd.merge(df2, matrixssl, on=['CA'])
    result = pd.merge(df3, nss, on=['CA'])
    print(result.shape)
    # gnutls_ca = list(result['CA'].values)
    # print(list(set(openssl_ca).difference(set(gnutls_ca))))
    # result.columns=['CA','openssl','polarssl','GNUTLS']
    result['cons']=result.apply(lambda x:1 if x.openssl_acc == x.polarssl_acc and x.openssl_acc ==x.gnutls_acc and x.openssl_acc ==x.matrixssl_acc and x.openssl_acc ==x.nss_acc else 0,axis=1)
    result.to_csv(os.path.join(result_path, 'result_nss.csv'), index=None, encoding='utf-8')

def nss_result_combine():
    s_result_folder = conf.HOME_DIR+'utils/'
    result_path = conf.HOME_DIR+'utils/'
    nss_result_merge(s_result_folder,result_path)

def nss_encode(res):
    global error_encode_count
    
    openssl_dict = {
        "None":"0",
        " parsing errors\n\n":"1",
        " error 7 at 0 depth lookup:certificate signature failure\n\n":"2",
        " error 18 at 0 depth lookup:self signed certificate\n\n":"3",
        " error 10 at 0 depth lookup:certificate has expired\n\n":"4",
        " error 20 at 0 depth lookup:unable to get local issuer certificate\n\n":"5",
        " error 34 at 0 depth lookup:unhandled critical extension\n\n":"6",
        " unexpected reason\n\n":"7",
    }

    polarssl_dict = {
        "None":"0",
        " parsing errors\n\n":"1",
        " self-signed or not signed by a trusted CA\n\n":"2",
        " server certificate has expired\n\n":"3",
        " unexpected reason\n\n":"4",
    }

    gnutls_dict = {
        "None":"0",
        " parsing errors\n\n":"1",
        " The certificate issuer is unknown\n\n":"2",
        " expired certificate\n\n":"3",
        " invalid signature\n\n":"4",
        " unexpected reason\n\n":"5",
    }

    matrixssl_dict = {
        "None":"0",
        " authStatus FAIL Distinguished Name Match\n\n":"1",
        " FAIL Auth Key / Subject Key Match\n\n":"2",
        " FAIL Extension (KEY_USAGE )\n\n":"3",
        " FAIL parse\n\n":"4",
        " unexpected reason\n\n":"5",
    }

    nss_dict = {
        "None":"0",
        " Certificate key usage inadequate for attempted operation\n\n":"1",
        " uld not decode certificate\n\n":"2",
        " Peer's Certificate issuer is not recognized\n\n":"3",
        " Peer's certificate issuer has been marked as not trusted by the user\n\n":"4",
        " Certificate type not approved for application\n\n":"5",
        " Issuer certificate is invalid\n\n":"6",
        " Certificate contains unknown critical extension\n\n":"7",
        " improperly formatted DER-encoded message\n\n":"8",        
        " unexpected reason\n\n":"9",
    }
    try:
        res_code = openssl_dict[res[2]] + polarssl_dict[res[4]] + gnutls_dict[res[6]] + matrixssl_dict[res[8]] + nss_dict[res[10]]
    except:
        error_encode_count += 1
        return None

    return res_code

def nss_result_analysis():
    result_path = conf.HOME_DIR+'utils/result_nss.csv'
    result = pd.read_csv(result_path)
    result = result.values
    cons = result[:,-1]
    VDIF = cons.shape[0] - cons.sum()
    print('VDIF:',VDIF)
    
    UDIF = []
    for i in range(result.shape[0]):
        if cons[i] == 1:
            continue
        res = nss_encode(result[i])
        if res not in UDIF and res != None:
            UDIF.append(res)
    print('UDIF', len(UDIF))
    print('error_encode_count', error_encode_count)

if __name__ == '__main__':
    mode = sys.argv[1]
    if mode == 'split':
        split_certs()
    if mode == 'test':
        nss_test_certs()
    if mode == 'combine':
        nss_result_combine()
    if mode == 'analysis':
        nss_result_analysis()
        