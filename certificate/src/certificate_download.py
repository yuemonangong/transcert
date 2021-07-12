#-*- Coding: utf-8 -*-

import sys
import ssl
import socket
import OpenSSL.crypto as crypto
import time
def mailsmsPoC(url,target_folder):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((url, 443))
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        s = context.wrap_socket(s, server_hostname=url)
        cert = s.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1,cert)
        dump_cert = crypto.dump_certificate(crypto.FILETYPE_PEM,x509)
        with open(target_folder+url+'.pem', 'a') as f:
            f.write(dump_cert.decode('utf-8'))
        s.close()

if __name__=="__main__":
    filepath = sys.argv[1]
    target_folder = sys.argv[2]
    file = open(filepath, 'r')
    for f in file.readlines():
        url = f.strip('\r\n')
        try:
            url = f.strip('\r\n')
            mailsmsPoC(url,target_folder)
            time.sleep(0.01)
        except:
            #error_lists.append(url)
            print("time out")
            continue

