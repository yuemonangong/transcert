import conf
import os
import shutil


def open_polar_accept(filepath,mode):
    flag = False
    with open(filepath, 'r') as result:
        buf = result.read()
        start = buf.find('-----START VERIFYING', 0)
        end = buf.find('-----END VERIFYING', start + 1)
        body = buf[start: end]
        if mode == 0:
            if (body.find('.pem: OK')>=0):
                flag = True
        elif mode == 1:
            if (body.endswith('ok\n')):
                flag = True
        elif mode == 2:
            if (body.find('Chain verification output: Verified. The certificate is trusted.') >= 0):
                flag = True
        else:
            if (body.find('PASS') >=0):
                flag = True
    result.close()
    return flag

def open_polar_parse(filepath,mode):
    #mode =0 is openssl,mode =1 is polarssl,mode=2 is gnutls
    flag = True
    with open(filepath, 'r') as result:
        buf = result.read()
        if mode == 0:
           if (buf.find('unable to load certificate') >= 0):
                flag = False
        elif mode == 1:
           if (buf.find('Loading the certificate(s) ... failed')>=0):
                flag = False
        else:
           if (buf.find('error parsing') >= 0):
                flag = False
    return flag
