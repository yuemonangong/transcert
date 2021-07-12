#!/usr/bin/env python

#Partially reuse some files in frankencert, see https://github.com/sumanj/frankencert.

import os
from OpenSSL import crypto
import subprocess
import sys
import franken_conf_parse
import conf
from datetime import datetime,timedelta
import json
import shutil

# set up some global variables
n_outcert = 0
pkeys = []



signed_by_CA = 0   #how many certs are signed by CA?
signed_by_self = 0 #how many certs are signed by itself?

franken_names = []


def gen_pkeys(): #frankencert
    pkeys = []
    fconf = franken_conf_parse.parse_config()
    public_key_len = fconf["public_key_len"]    
    max_depth = 100
    for i in range(max_depth):
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, public_key_len)
        pkeys.append(pkey) 
    return pkeys  



# load the certs in a file, by Yuting
def load_file(filepath):#path, name
    chain = []
    with open(filepath, "r") as f:
        buf = f.read()
        index1 = 0
        start = buf.find('-----BEGIN CERTIFICATE-----', index1)
        end = buf.find('-----END CERTIFICATE-----', start)      
        
        while start >= 0:    
            buf1 = buf[start:end + 25]
                        
            try:
                seed0 = crypto.load_certificate(crypto.FILETYPE_PEM, buf1)
                chain.insert(0, seed0)
            except:
                print("Skipping: " + filepath)
            index1 = start + 1
            start = buf.find('-----BEGIN CERTIFICATE-----', index1)
            end = buf.find('-----END CERTIFICATE-----', start)

    return chain
      
# write out all the certs
def dump_certs(certs, prefix, path, name_begin=0): #frankencert
    for i, cert in enumerate(certs):
        key, certs = cert
        with open(os.path.join(path, "%s-%d.pem" % (prefix, name_begin + i)), \
                   "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
            for cert in certs:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

# write a chain into a cert file
# input: the target_filepath

def dump_cert(certs, target_filepath):
    with open(target_filepath, "wb") as f:
            #f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
            for cert in certs:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))    


# load all certs from a directory
def load_dir(path):      #frankencert
    certs = []        
    files = os.listdir(path)
    nfiles = len(files)                                               
    files = map(lambda f : os.path.join(path, f), files)
    step = max(1, nfiles / 10)
    count = 0
    sys.stdout.write("Loading seed certificates") 
    for infile in files:
        count = (count + 1) % step
        if (count == 0):
            sys.stdout.write(".") 
            sys.stdout.flush()
        with open(infile) as f:
            buf = f.read()
            try:
                certs.append(crypto.load_certificate(crypto.FILETYPE_PEM, buf))
            except:
                print("Skipping: " + infile)
    sys.stdout.write("\n")
    #sys.stdout.flush()
 
    return certs

# recycle an existing certfile containing arbitrarily long cert chains 
# with new CA  
def recycle_cert(inpath, outpath, cafile, fix_timestamps): #frankencert
    incerts = []
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
    
    #print(len(incerts))
   
    pkeys = [] 
    for i in range(len(incerts)):
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 2048)
        pkeys.append(pkey)
    
    for i in range(len(incerts)):
        incerts[i].set_pubkey(pkeys[i])
        if (fix_timestamps):
            now = datetime.now().strftime("%Y%m%d%H%M%SZ")
            expire = (datetime.now() + timedelta(days=100))\
                   .strftime("%Y%m%d%H%M%SZ")
            now = bytes(now, encoding = "utf8")
            expire = bytes(expire, encoding = "utf8")
            incerts[i].set_notBefore(now)
            incerts[i].set_notAfter(expire)
   
        if (i == len(incerts) - 1): 
            incerts[i].set_issuer(cacert.get_subject())
            incerts[i].sign(cakey, "sha256")
        else:    
            incerts[i].set_issuer(incerts[i + 1].get_subject())
            incerts[i].sign(pkeys[i + 1], "sha256")

    
    with open(outpath, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkeys[0]))
        for i in range(len(incerts)):
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, incerts[i]))

# Print all certs in a file, openssl x509 only prints the first one 
# Uses the openssl x509 command, pretty hacky but it works 
def print_cert(inpath): #frankencert
    output = ""

    with open(inpath) as f:
        buf = f.read()
        pattern = "-----BEGIN CERTIFICATE-----"
        index = 0
        i = 0
        while True:
            index = buf.find(pattern, index)
            if (index == -1):
                break
            p = subprocess.Popen(["openssl", "x509", "-text"], \
                            stdout=subprocess.PIPE, stdin=subprocess.PIPE, \
                            stderr=subprocess.STDOUT)
            output += p.communicate(input=buf[index:])[0]
            index = index + len(pattern)
            i += 1
    #print (output.find("Certificate:"))
    #print (output )


def load_json(filepath):#,filetype):
    with open (filepath,'r') as f:
        content = json.load(f)
    f.close()
    return content


def dump_json(content,filename):
     with open(filename,'w') as f:
          json.dump(content,f,default=lambda o: o.__dict__,indent = 4)
     f.close()

def get_cov(filepath):
    line_cov = 0
    branch_cov = 0
    with open(filepath,'rb') as f:
        for line in f:
            if line.startswith(b'  lines'):
                index0 = line.find(b'(')
                index1 = line.find(b' ',index0)
                line_cov = int(line[index0+1:index1])
            if line.startswith(b'  branches'):
                index0 = line.find(b'(')
                index1 = line.find(b' ',index0)
                branch_cov = int(line[index0+1:index1])
    return line_cov,branch_cov

#<stmt,bran>#


def get_func_set(filepath):
    funcs = []
    with open(filepath,'rb') as f:
        for line in f.readlines():
            func_name = line.split(',')[1]
            funcs.append(func_name)
    f.close()
    funcs = set(funcs)
    return funcs


