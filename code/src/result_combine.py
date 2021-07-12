import os
import pandas as pd
import sys
#import mucert_util
import numpy
import json
import shutil

def load_json(filepath):  # ,filetype):
        with open(filepath, 'r') as f:
            content = json.load(f)
        f.close()
        return content

#file_cov = load_json('/home/stats/func/file_cov_0_func.json')
#modify_log = load_json('/home/stats/func/mod_log_0_func.json')
#stat_cov = mucert_util.load_json('../util/stat/cov_stat_0.json')
operation_dict = {"-4":"delete notAfter",
                  "-3":"delete notBefore",
                  "-2":"delete serial_number",
                  "-1":"delete subject",
                  "0":"delete extensions",
                  "1":"update notAfter",
                  "2":"update notBefore",
                  "3":"update serial_number",
                  "4":"update subject",
                  "5":"update countryName in subject",
                  "6":"update stateOrProvinceName in subject",
                  "7":"update localityName in subject",
                  "8":"update organizationName in subject",
                  "9":"update organizationalUnitName in subject",
                  "10":"update commonName in subject",
                  "11":"update emailAddress in subject",
                  "12":"update name in subject",
                  "13":"update title in subject",
                  "14":"delete countryName in subject",
                  "15":"delete stateOrProvinceName in subject",
                  "16":"delete localityName in subject",
                  "17":"delete organizationName in subject",
                  "18":"delete organizationalUnitName in subject",
                  "19":"delete commonName in subject",
                  "20":"delete emailAddress in subject",
                  "21":"delete name in subject",
                  "22":"delete title in subject",
                  "23":"append a cert",
                  "24":"insert a cert after which_cert_in_chain",
                  "25":"insert a cert before which_cert_in_chain",
                  "26":"delete a cert at which_cert_in_chain",
                  "27":"update a cert",
                  "28":"append a set of extensions",
                  "29":"append one extension",
                  "30":"update one extension",
                  "31":"update critical of one extension",
                  "32":"update data of one extension"
}

def reason_extract(line):
    content = line.lstrip('-----')
    l_content = content.split('-----')
    reason = " "
    for i in range(1,len(l_content)):
        reason += l_content[i].lstrip("reject for")
        reason += '\n'
    return reason

def txt_table(filepath,mode):
    df = pd.DataFrame()
    with open(filepath,'r') as f:
        for line in f.readlines():
            # line = line.decode('utf-8')
            ca_name = line.split('-----')[1].lstrip('START VERIFYING ').rstrip('.pem')
            if line.find('reject') != -1:
                accept_bool = 'F'
                r_reason = reason_extract(line)
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
    return df

def result_merge(s_result_folder,result_path):
    gnutls = txt_table(os.path.join(s_result_folder, 's_gnutls.txt'), mode='2')
    openssl = txt_table(os.path.join(s_result_folder, 's_openssl.txt'), mode='0')
    polarssl = txt_table(os.path.join(s_result_folder, 's_polarssl.txt'), mode='1')
    matrixssl = txt_table(os.path.join(s_result_folder, 's_matrixssl.txt'), mode='3')
    print(gnutls.shape)
    print(openssl.shape)
    print(polarssl.shape)
    print(matrixssl.shape)
    df = pd.merge(openssl, polarssl, on=['CA'])#remove state keys
    # df.columns= ['CA','openssl','polarssl']
    openssl_ca = list(df['CA'].values)
    df2 = pd.merge(df, gnutls, on=['CA'])#remove state keys
    result = pd.merge(df2, matrixssl, on=['CA'])
    print(result.shape)
    # gnutls_ca = list(result['CA'].values)
    # print(list(set(openssl_ca).difference(set(gnutls_ca))))
    # result.columns=['CA','openssl','polarssl','GNUTLS']
    result['cons']=result.apply(lambda x:1 if x.openssl_acc == x.polarssl_acc and x.openssl_acc ==x.gnutls_acc and x.openssl_acc ==x.matrixssl_acc else 0,axis=1)
    result.to_csv(os.path.join(result_path, 'result.csv'), index=None, encoding='utf-8')

'''
#print the modification history of filelog
def his_print(filename):
    fileindex = int(filename.split('.')[0])
    filelog = []
    while fileindex > 1005:
        operation = modify_log[filename]['operation']
        filelog.append(operation_dict[str(operation)])
        filename = modify_log[filename]['origin']
        fileindex = int(filename.split('.')[0])
    filelog.reverse()
    for i in range(len(filelog)):
        print(filelog[i])

'''

if __name__=='__main__':
    #merge difference_testing results
    s_result_folder = sys.argv[1]
    result_path = sys.argv[2] # the file path for the simplified result path 
    result_merge(s_result_folder,result_path)

    #filepath = sys.argv[1]
    #result_unconsis_classify(filepath)
    #result_stat(filepath)
    #print history log
    #filename = "6463.pem"
    #his_print(filename)

