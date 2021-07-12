import OpenSSL.crypto as crypto
import os
import pandas as pd
import sys

def get_name(subject):
    subject_country = subject.C
    subject_state = subject.ST
    subject_locality = subject.L
    subject_o = subject.O
    subject_OU = subject.OU
    subject_CN = subject.CN
    subject_email = subject.emailAddress
    subject_name = "C=" + str(subject_country) + ",ST=" + str(subject_state) + ",L=" + str(
        subject_locality) + ",O=" + str(subject_o) + ",OU=" + str(subject_OU) + \
                   ",CN=" + str(subject_CN) + ",email=" + str(subject_email)
    return subject_name



def get_extension(x509_cert,pem_name,extension_csv):
    pem_id = pem_name.rstrip('.pem')
    for i in range(x509_cert.get_extension_count()):
        extension = x509_cert.get_extension(i)
        bool_critical = str(extension.get_critical())
        extension_name = str(extension.get_short_name())
        #print(extension_name)
        try:
           extension_data = extension.__str__()
           extension_result = pd.DataFrame([pem_id,str(i+1),bool_critical,extension_name,extension_data]).T
           if not os.path.exists(extension_csv):
                 extension_result.columns=['pem_id','ext_id','critical','name','data']
                 extension_result.to_csv(extension_csv,index=None,mode='a',encoding='utf-8')
           else:
                 extension_result.to_csv(extension_csv,header=None,index=None, mode='a', encoding='utf-8')
        except:
            continue
       # print(extension_data)

    #return(file_name,extension_id,bool_critical,extension_name,extension_data)

def parse_cert(pem_folder,pem_name,cert_parse_csv,extension_parse_csv):
    with open(os.path.join(pem_folder,pem_name), 'r') as f:
        cert = f.read().encode('utf-8')
    f.close()
    cert_id = pem_name.rstrip('.pem')
    x509_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    version = x509_cert.get_version()
    subject = x509_cert.get_subject()
    subject_name= get_name(subject)
    issuer = x509_cert.get_issuer()
    issuer_name = get_name(issuer)
    serial_number= x509_cert.get_serial_number()
    signature_alg=x509_cert.get_signature_algorithm()
    time_before = x509_cert.get_notBefore()
    time_after= x509_cert.get_notAfter()
    cert_parse_result = pd.DataFrame([cert_id,version,signature_alg,serial_number,subject_name,issuer_name,time_before,time_after]).T
    if not os.path.exists(extension_parse_csv):
        cert_parse_result.columns=['cert_id','version','sig_alg','serial_number','sub_name','issuer_name','time_bfr','time_aft']
        cert_parse_result.to_csv(cert_parse_csv,index=None,mode='a',encoding='utf-8')
    else:
        cert_parse_result.to_csv(cert_parse_csv, header=None,index=None, mode='a', encoding='utf-8')
    get_extension(x509_cert,pem_name,extension_parse_csv)


def rename(filefolder):
    filelists = os.listdir(filefolder)
    index = 0
    for file in filelists:
        os.rename(os.path.join(filefolder,file),os.path.join(filefolder,str(index)+'.pem'))
        index += 1


pem_folder = sys.argv[1]
pems = os.listdir(pem_folder)
for pem_name in pems:
    parse_cert(pem_folder, pem_name, 'corpus.csv', 'corpus_extensions.csv')
