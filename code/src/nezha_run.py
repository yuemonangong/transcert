# Partially reuse some files in frankencert, see https://github.com/sumanj/frankencert.
# A reproduction of Nezha's black box method, using mucert's mutators instead of libfuzzer. See https://ieeexplore.ieee.org/abstract/document/7958601/.

from OpenSSL import crypto
import random
import collections
import sys
import os
import franken_conf_parse
import mucert_util
import conf
from datetime import datetime, timedelta
import math
import parsing_filter

import numpy as np
import pandas as pd
import base64
import shutil
import random

from nss import split_cert, nss_test_cert, nss_txt_table

#signed_by_CA = False
#certificates = mucert_util.load_dir(conf.input_cert_path)
#mucert_util.pkeys = mucert_util.gen_pkeys()

def get_extension_dict(certs):  # frankencert
    d = collections.defaultdict(dict)
    for cert in certs:
        extensions = get_extensions(cert)
        for i, extension in enumerate(extensions):
            """
            PyOpenSSL's get_short_name return UNKN for all unknown extensions
            This is bad for a mapping, our patched PyOpenSSL code has a 
            get_oid function.
            """
            d[extension.get_oid()][extension.get_data()] = extension
    for k in d.keys():
        d[k] = d[k].values()
    return d

def get_extensions(cert):  # frankencert
    return [cert.get_extension(i) \
            for i in range(0, cert.get_extension_count())]

# using a cert in certificates to update a cert in seed_certs
# recursively generate a new seed
def nezha_update_certs(filefolder, filename,root_pem_folder,leaf_pem_folder,target_name):
    # may have no chain
    # (1) select one seed file and a pick cert
    chain = mucert_util.load_file(os.path.join(filefolder, filename))  # may have no chain

    pick_file = random.choice(os.listdir(conf.input_cert_path))
    pick_chain = mucert_util.load_file(os.path.join(conf.input_cert_path, pick_file))
    pick_cert = pick_chain[random.randint(0, len(pick_chain) - 1)]
    target_filepath = os.path.join(filefolder, target_name)
    with open(conf.ca_cert_path, 'rt') as ca_cert_file:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_file.read())

    with open(conf.ca_cert_path, 'rt') as ca_key_file:
        ca_private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, \
                                                ca_key_file.read())
    fconf = franken_conf_parse.parse_config()

    # (2) generate a new seed file
    (updatecerts, operation) = update_cert(chain, pick_cert, certificates, ca_cert, ca_private_key, fconf, None)
    if updatecerts is None:
        return
    certs = updatecerts
    if len(certs) >= 2:
        leaf_pem = []
        leaf_pem.append(certs[0])
        root_pem =certs[1:]#from the first cert
        root_pem.append(ca_cert)
        root_targetpath = os.path.join(root_pem_folder,target_name)
        leaf_targetpath = os.path.join(leaf_pem_folder,target_name)
        mucert_util.dump_cert(list(root_pem),root_targetpath)
        mucert_util.dump_cert(list(leaf_pem),leaf_targetpath)
    mucert_util.dump_cert(updatecerts, target_filepath)
    if os.path.exists(conf.modify_log_path):
        modify_log = mucert_util.load_json(conf.modify_log_path)
    else:
        modify_log = {}
    modify_log[target_name] = {}
    modify_log[target_name]['origin'] = filename
    modify_log[target_name]['operation'] = operation
    modify_log[target_name]['corpus'] = pick_file
    mucert_util.dump_json(modify_log, conf.modify_log_path)

def generate_with_extensions(cert, new_extensions):
    new_cert = crypto.X509()
    new_cert.set_version(2)
    if (not cert.get_notBefore() is None):
        new_cert.set_notBefore(cert.get_notBefore())
    if (not cert.get_notAfter() is None):
        new_cert.set_notAfter(cert.get_notAfter())
    if (not cert.get_subject() is None):
        new_cert.set_subject(cert.get_subject())
    if (not cert.get_serial_number() is None):
        new_cert.set_serial_number(cert.get_serial_number())
    new_cert.add_extensions(new_extensions)
    return new_cert

# delete a field from a certificate structure
def delete_field_X509(cert, field):
    new_cert = crypto.X509()
    new_cert.set_version(2)
    if (not field is "notBefore") and (not cert.get_notBefore() is None):
        new_cert.set_notBefore(cert.get_notBefore())
    if (not field is "notAfter") and (not cert.get_notAfter() is None):
        new_cert.set_notAfter(cert.get_notAfter())
    if (not field is "subject") and (not cert.get_subject() is None):
        new_cert.set_subject(cert.get_subject())
    if (not field is "serial_number") and (not cert.get_serial_number() is None):
        new_cert.set_serial_number(cert.get_serial_number())
    if (not field is "extensions"):
        extensions = []
        for i in range(cert.get_extension_count()):
            extension = cert.get_extension(i)
            extensions.append(extension)
        new_cert.add_extensions(extensions)
    return new_cert

# Delete a field from a name subject. We delete a subject field by cloning the subject.
# Notice that a filed may have a length limit.
# define ub_name		32768
# define ub_common_name		64
# define ub_locality_name	128
# define ub_state_name		128
# define ub_organization_name	64
# define ub_organization_unit_name	64
# define ub_title		64
# define ub_email_address	128
def delete_field_X509Name(subject, field):
    new_cert = crypto.X509()
    new_cert.set_version(2)
    new_subject = crypto.X509Name(new_cert.get_subject())

    if (not subject.name is None) and (not field is "name"):
        if len(subject.name) <= 32768:
            new_subject.name = subject.name
        else:
            new_subject.name = (subject.name)[:32768]

    if (not subject.title is None) and (not field is "title"):
        if len(subject.title) <= 64:
            new_subject.title = subject.title
        else:
            new_subject.title = (subject.title)[:64]

    if (not subject.countryName is None) and (not field is "countryName"):
        new_subject.countryName = subject.countryName

    if (not subject.stateOrProvinceName is None) and (not field is "stateOrProvinceName"):
        if len(subject.stateOrProvinceName) <= 128:
            try:                                                                                                    # add ver.1
                new_subject.stateOrProvinceName = subject.stateOrProvinceName
            except:                                                                                                 # add ver.1
                new_subject = delete_field_X509Name(new_subject, "stateOrProvinceName")                                 # add ver.1
        else:
            new_subject.stateOrProvinceName = (subject.stateOrProvinceName)[:128]

    if (not subject.localityName is None) and (not field is "localityName"):
        if len(subject.localityName) <= 128:
            new_subject.localityName = subject.localityName
        else:
            new_subject.localityName = (subject.localityName)[:128]

    if (not subject.organizationName is None) and (not field is "organizationName"):
        if len(subject.organizationName) <= 64:
            new_subject.organizationName = subject.organizationName
        else:
            new_subject.organizationName = (subject.organizationName)[:64]

    if (not subject.organizationalUnitName is None) and (not field is "organizationalUnitName"):
        if len(subject.organizationalUnitName) <= 64:
            new_subject.organizationalUnitName = subject.organizationalUnitName
        else:
            new_subject.organizationalUnitName = (subject.organizationalUnitName)[:64]

    if (not subject.commonName is None) and (not field is "commonName"):
        if len(subject.commonName) <= 64:
            new_subject.commonName = subject.commonName
        else:
            new_subject.commonName = (subject.commonName)[:64]

    if (not subject.emailAddress is None) and (not field is "emailAddress"):
        if len(subject.emailAddress) <= 128:
            new_subject.emailAddress = subject.emailAddress
        else:
            new_subject.emailAddress = (subject.emailAddress)[:128]
    return new_subject

def delete_extension(certificate,index):
    new_extensions = []
    count = certificate.get_extension_count()
    for i in range(count):
        extension = certificate.get_extension(i)
        if i == index:
            continue
        else:
            new_extensions.append(extension)
    return new_extensions

# using a field of pick_cert to update a cert in chain
def update_cert(chain, pick_cert, certificates, ca_cert, ca_key, fconfig, \
                extensions=None):
    flip_probability = fconfig["flip_critical_prob"]
    sign_mode = 1  # we can sign (1) after or (2)before mutation. We remove the code for signing before mutation.

    # generate the key pairs once and reuse them for faster
    # frankencert generation
    max_depth = fconfig["max_depth"]

    max_extensions = fconfig["max_extensions"]
    if extensions is None:
        extensions = get_extension_dict(certificates)
    max_extensions = min(max_extensions, len(extensions.keys()))

    if len(chain) < 1:
        return None, None

    which_cert_in_chain = 0
    if len(chain) > 1:
        which_cert_in_chain = random.randint(0, len(chain) - 1)  # select a cert

    which_operation = random.randint(-4, 32)  # select an operation
    subject = chain[which_cert_in_chain].get_subject()

    if which_operation == -4:  # print "<--------------delete notAfter"
        chain[which_cert_in_chain] = delete_field_X509(chain[which_cert_in_chain], "notAfter")
    elif which_operation == -3:  # print "<--------------delete notBefore"
        chain[which_cert_in_chain] = delete_field_X509(chain[which_cert_in_chain], "notBefore")
    elif which_operation == -2:  # print "<--------------delete serial_number"
        chain[which_cert_in_chain] = delete_field_X509(chain[which_cert_in_chain], "serial_number")
    elif which_operation == -1:  # print "<--------------delete subject"
        chain[which_cert_in_chain] = delete_field_X509(chain[which_cert_in_chain], "subject")
    elif which_operation == 0:  # print "<--------------delete extensions"
        chain[which_cert_in_chain] = delete_field_X509(chain[which_cert_in_chain], "extensions")
    if which_operation == 1:  # print "<--------------update notAfter"
        if (not pick_cert.get_notAfter() is None):
            expired = pick_cert.get_notAfter()
            expired_time = datetime.strptime(str(expired[0:8])[2:-1], '%Y%m%d')
            print('expired_time', expired_time)
            if (expired_time - datetime.now()).days < 0:
                add_day = random.randint(1, 100)
                expired = (datetime.now() + timedelta(days=add_day)).strftime("%Y%m%d%H%M%SZ")
                print('expired', expired)
            chain[which_cert_in_chain].set_notAfter(expired)
    elif which_operation == 2:  # print "<--------------update notBefore"
        if (not pick_cert.get_notBefore() is None):
            chain[which_cert_in_chain].set_notBefore(pick_cert.get_notBefore())
    elif which_operation == 3:  # print "<--------------update serial_number"
        if (not pick_cert.get_serial_number() is None):
            chain[which_cert_in_chain].set_serial_number(pick_cert.get_serial_number())
    elif which_operation == 4:  # print "<--------------update subject"
        if (not pick_cert.get_subject() is None):
            chain[which_cert_in_chain].set_subject(pick_cert.get_subject())

    # update a field in a subject
    elif which_operation == 5:  # print "<--------------update countryName in subject"
        if not pick_cert.get_subject().countryName is None:
            subject.countryName = pick_cert.get_subject().countryName
        else:
            new_subject = delete_field_X509Name(subject, "countryName")
            chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 6:  # print "<--------------update stateOrProvinceName in subject"
        if not pick_cert.get_subject().stateOrProvinceName is None:
            if len(pick_cert.get_subject().stateOrProvinceName) <= 128:
                try:                                                                                                    # add ver.1
                    subject.stateOrProvinceName = pick_cert.get_subject().stateOrProvinceName
                except:                                                                                                 # add ver.1
                    new_subject = delete_field_X509Name(subject, "stateOrProvinceName")                                 # add ver.1
                    chain[which_cert_in_chain].set_subject(new_subject)                                                 # add ver.1
            else:
                subject.stateOrProvinceName = (pick_cert.get_subject().stateOrProvinceName)[:128]
        else:
            new_subject = delete_field_X509Name(subject, "stateOrProvinceName")
            chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 7:  # print "<--------------update localityName in subject"
        if not pick_cert.get_subject().localityName is None:
            if len(pick_cert.get_subject().localityName) <= 128:
                subject.localityName = pick_cert.get_subject().localityName
            else:
                subject.localityName = (pick_cert.get_subject().localityName)[:128]
        else:
            new_subject = delete_field_X509Name(subject, "localityName")
            chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 8:  # print "<--------------update organizationName in subject"
        if not pick_cert.get_subject().organizationName is None:
            if len(pick_cert.get_subject().organizationName) <= 64:
                subject.organizationName = pick_cert.get_subject().organizationName
            else:
                subject.organizationName = (pick_cert.get_subject().organizationName)[:64]
        else:
            new_subject = delete_field_X509Name(subject, "organizationName")
            chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 9:  # print "<--------------update organizationalUnitName in subject"
        if not pick_cert.get_subject().organizationalUnitName is None:
            if len(pick_cert.get_subject().organizationalUnitName) <= 64:
                subject.organizationalUnitName = pick_cert.get_subject().organizationalUnitName
            else:
                subject.organizationalUnitName = (pick_cert.get_subject().organizationalUnitName)[:64]
        else:
            new_subject = delete_field_X509Name(subject, "organizationalUnitName")
            chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 10:  # print "<--------------update commonName in subject"
        if not pick_cert.get_subject().commonName is None:
            if len(pick_cert.get_subject().commonName) <= 64:
                subject.commonName = pick_cert.get_subject().commonName  # "127.0.0.1"
            else:
                subject.commonName = (pick_cert.get_subject().commonName)[:64]  # "127.0.0.1"
        else:
            new_subject = delete_field_X509Name(subject, "commonName")
            chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 11:  # print "<--------------update emailAddress in subject"
        if not pick_cert.get_subject().emailAddress is None:
            if len(pick_cert.get_subject().emailAddress) <= 128:
                subject.emailAddress = pick_cert.get_subject().emailAddress
            else:
                subject.emailAddress = (pick_cert.get_subject().emailAddress)[:128]
        else:
            new_subject = delete_field_X509Name(subject, "emailAddress")
            chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 12:  # print "<--------------update name in subject"
        if not pick_cert.get_subject().name is None:
            if len(pick_cert.get_subject().name) <= 32768:
                subject.name = pick_cert.get_subject().name  # "127.0.0.1"
            else:
                subject.name = (pick_cert.get_subject().name)[:32768]  # "127.0.0.1"
        else:
            new_subject = delete_field_X509Name(subject, "name")
            chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 13:  # print "<--------------update title in subject"
        if not pick_cert.get_subject().title is None:
            if len(pick_cert.get_subject().title) <= 64:
                subject.title = pick_cert.get_subject().title  # "127.0.0.1"
            else:
                subject.title = (pick_cert.get_subject().title)[:64]  # "127.0.0.1"
        else:
            new_subject = delete_field_X509Name(subject, "title")
            chain[which_cert_in_chain].set_subject(new_subject)
        # complete updating a field in a subject
    # delete a field in subject
    elif which_operation == 14:  # print "<--------------delete countryName in subject"
        new_subject = delete_field_X509Name(subject, "countryName")
        chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 15:  # print "<--------------delete stateOrProvinceName in subject"
        new_subject = delete_field_X509Name(subject, "stateOrProvinceName")
        chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 16:  # print "<--------------delete localityName in subject"
        new_subject = delete_field_X509Name(subject, "localityName")
        chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 17:  # print "<--------------delete organizationName in subject"
        new_subject = delete_field_X509Name(subject, "organizationName")
        chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 18:  # print "<--------------delete organizationalUnitName in subject"
        new_subject = delete_field_X509Name(subject, "organizationalUnitName")
        chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 19:  # print "<--------------delete commonName in subject"
        new_subject = delete_field_X509Name(subject, "commonName")
        chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 20:  # print "<--------------delete emailAddress in subject"
        new_subject = delete_field_X509Name(subject, "emailAddress")
        chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 21:  # print "<--------------delete name in subject"
        new_subject = delete_field_X509Name(subject, "name")
        chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 22:  # print "<--------------delete title in subject"
        new_subject = delete_field_X509Name(subject, "title")
        chain[which_cert_in_chain].set_subject(new_subject)
        # complete deletion a field in a subject

    # update one cert in a chain
    elif which_operation == 23:  # print "<--------------append a cert"
        pick_cert.set_issuer(chain[len(chain) - 1].get_subject())
        chain.append(pick_cert)
    elif which_operation == 24:  # print "<--------------insert a cert aftet which_cert_in_chain"
        pick_cert.set_issuer(chain[which_cert_in_chain].get_subject())
        if (which_cert_in_chain < len(chain) - 1):  # not the last one
            chain[which_cert_in_chain + 1].set_issuer(pick_cert.get_subject())
        chain.insert(which_cert_in_chain + 1, pick_cert)
    elif which_operation == 25:  # print "<--------------insert a cert before which_cert_in_chain"
        pick_cert.set_issuer(chain[which_cert_in_chain].get_issuer())
        chain[which_cert_in_chain].set_issuer(pick_cert.get_subject())
        chain.insert(which_cert_in_chain, pick_cert)
    elif which_operation == 26:  # print "<--------------delete a cert at which_cert_in_chain"
        if (len(chain) <= 1):  # we cannot delete the only cert
            pass
        else:
            if (which_cert_in_chain + 1 < len(chain)):
                chain[which_cert_in_chain + 1].set_issuer(chain[which_cert_in_chain].get_issuer())
            del chain[which_cert_in_chain]
    elif which_operation == 27:  # print "<--------------update a cert"
        pick_cert.set_issuer(chain[which_cert_in_chain].get_issuer())
        if (which_cert_in_chain + 1 < len(chain)):
            chain[which_cert_in_chain + 1].set_issuer(pick_cert.get_subject())
        chain[which_cert_in_chain] = pick_cert
        # complete updating one cert in the chain

    # update extension
    elif which_operation == 28:  # print "<--------------append a set of extensions"
        new_extensions = []
        for i in range(pick_cert.get_extension_count()):
            extension = pick_cert.get_extension(i)
            new_extensions.append(extension)
        chain[which_cert_in_chain].add_extensions(new_extensions)
    elif which_operation == 29:  # print "<--------------append one extension"
        new_extensions = []
        count_pick = pick_cert.get_extension_count()

        if (count_pick < 1):
            pass
        else:
            index_pick = 0

            if count_pick > 1:
                index_pick = random.randint(0, count_pick - 1)
            extension = pick_cert.get_extension(index_pick)
            new_extensions.append(extension)

        chain[which_cert_in_chain].add_extensions(new_extensions)
    elif which_operation >= 30 and which_operation <= 32:  # print "<--------------update one extension"
        new_extensions = []
        for i in range(chain[which_cert_in_chain].get_extension_count()):
            extension = chain[which_cert_in_chain].get_extension(i)
            new_extensions.append(extension)

        count_cert = len(new_extensions)
        count_pick = pick_cert.get_extension_count()

        if (count_cert < 1 or count_pick < 1):
            pass
        else:
            index_cert = 0
            index_pick = 0
            if count_cert > 1:
                index_cert = random.randint(0, count_cert - 1)

            if count_pick > 1:
                index_pick = random.randint(0, count_pick - 1)

            if which_operation == 30:
                new_extensions[index_cert] = pick_cert.get_extension(index_pick)
            elif which_operation == 31:  # print "<--------------update critical of one extension"
                new_extensions[index_cert].set_critical(pick_cert.get_extension(index_pick).get_critical())
            elif which_operation == 32:  # print "<--------------update data of one extension"
                new_extensions[index_cert].set_data(pick_cert.get_extension(index_pick).get_data())
            chain[which_cert_in_chain] = generate_with_extensions(chain[which_cert_in_chain], new_extensions)
        # complete updating extensions
    elif which_operation == 33:  # print "<--------------do noting: other operations may be included here"
        pass

    key = None
    if sign_mode == 1:  # ****************mode 1: sign after mutation
        if len(chain) < 1:
            return None, None

        self_signed_probability = fconfig["self_signed_prob"]
        hash_for_sign_list = fconfig["hash_for_sign"]
        ######sign_algorithms add new requirements#########
        hash_for_sign = random.choice(hash_for_sign_list)#random.choice(hash_for_sign_list)random.choice(hash_for_sign_list.split(','))
        print('hash_for_sign', hash_for_sign)

        if random.random() >= self_signed_probability:  # sign by CA
            chain[0].set_issuer(ca_cert.get_subject())
            key = ca_key

            for i in range(0, len(chain)):
                chain[i].set_pubkey(mucert_util.pkeys[i % 3])
                chain[i].sign(key, hash_for_sign)
                key = mucert_util.pkeys[i % 3]
        else:
            chain[0].set_issuer(chain[0].get_subject())
            chain[0].set_pubkey(mucert_util.pkeys[0])
            key = mucert_util.pkeys[0]
            chain[0].sign(key, hash_for_sign)
            for i in range(1, len(chain)):
                chain[i].set_pubkey(mucert_util.pkeys[i % 3])
                chain[i].sign(key, hash_for_sign)
                key = mucert_util.pkeys[i % 3]
                # end of mode 1

    #certs = []
    #certs.append((key, list(reversed(chain))))

    return list(reversed(chain)), which_operation

def read_global_state(resfile):
    result = pd.read_csv(resfile)
    result = result.values
    result = result[:, 1:-1]
    GlobalState = []
    for i in range(result.shape[0]):
        res = list(result[i])
        if res not in GlobalState:
            GlobalState.append(res)
    return GlobalState

def get_pattern(fileid):
    # (1) verify the target file and save the outputs as files
    os.system("sh scripts/verify_single_file.sh "+str(fileid)+'.pem')

    try:
        split_cert(str(fileid)+'.pem', conf.seed_filefolder, conf.HOME_DIR+'utils/nss_seeds/', conf.ca_cert_path)
    except:
        pass
    nss_test_cert(str(fileid)+'.pem', conf.seed_filefolder, conf.HOME_DIR+'utils/nss_seeds/', conf.test_results_path, conf.ca_cert_path)

    # (2) simplify these files to a list pattern
    libs = ['openssl', 'polarssl', 'matrixssl', 'gnutls', 'nss']
    for idx in range(len(libs)):
        lib = libs[idx]
        pem_name = str(fileid)+ '_' + lib + '.txt'
        res_path = os.path.join(conf.test_results_path,pem_name)
        s_path = os.path.join(conf.test_results_path, 's_' + lib + '.txt')

        os.system('rm -rf ' + s_path)
        script_path = conf.HOME_DIR + 'src/simplify_results.py'
        os.system('python3 ' + script_path + ' ' + str(idx+1) + ' ' + res_path + ' >>' + s_path)
    
    gnutls = nss_txt_table(os.path.join(conf.test_results_path, 's_gnutls.txt'), mode='2')
    openssl = nss_txt_table(os.path.join(conf.test_results_path, 's_openssl.txt'), mode='0')
    polarssl = nss_txt_table(os.path.join(conf.test_results_path, 's_polarssl.txt'), mode='1')
    matrixssl = nss_txt_table(os.path.join(conf.test_results_path, 's_matrixssl.txt'), mode='3')
    nss = nss_txt_table(os.path.join(conf.test_results_path, 's_nss.txt'), mode='4')

    df = pd.merge(openssl, polarssl, on=['CA'])
    df2 = pd.merge(df, gnutls, on=['CA'])#remove state keys
    df3 = pd.merge(df2, matrixssl, on=['CA'])
    result = pd.merge(df3, nss, on=['CA'])
    result = result.values

    pattern = list(result[0, 1:])
    return pattern

def cov_restat(fileid,target_fileid,cov_stat):
    #used to update filecov and covstat
    file_cov = mucert_util.load_json(conf.file_cov_log)
    # origin_cov = file_cov[str(fileid)]
    line_cov,branch_cov = mucert_util.get_cov(os.path.join(conf.cov_results_path,str(target_fileid)+'.txt')) #line_cov
    cov = str((line_cov,branch_cov))
    file_cov[str(target_fileid)] = cov #update file_cov_0_line.json
    if cov not in cov_stat.keys():
            cov_stat[cov]= {}
            cov_stat[cov]['transfer_list'] = {}
            cov_stat[cov]['cnt'] = 1
            cov_stat[cov]['mod_cnt'] = 0
            cov_stat[cov]['fileids'] = [str(target_fileid)]
    else:
            cov_stat[cov]['cnt'] += 1
            cov_stat[cov]['fileids'].append(str(target_fileid))
    # cov_stat[origin_cov]['mod_cnt'] += 1
    # if cov not in cov_stat[origin_cov]['transfer_list'].keys():
            # cov_stat[origin_cov]['transfer_list'][cov] = 1
    # else:
            # cov_stat[origin_cov]['transfer_list'][cov] += 1
    mucert_util.dump_json(cov_stat,conf.cov_stat_log)
    mucert_util.dump_json(file_cov,conf.file_cov_log)


if __name__ == '__main__':
    signed_by_CA = False
    certificates = mucert_util.load_dir(conf.input_cert_path)
    mucert_util.pkeys = mucert_util.gen_pkeys()
    iteration = int(sys.argv[1])

    '''
    read GlobalState here
    result_nss.csv file must exist.
    '''
    GlobalState = read_global_state(conf.HOME_DIR + 'utils/result_nss.csv')

    nums = len(os.listdir(conf.seed_filefolder))
    iteration = iteration
    generation = 0
    while (generation < iteration):
        cov_stat = mucert_util.load_json(conf.cov_stat_log)
        print('generation', generation)
        print('globalstate num', len(GlobalState))
        
        fileid = random.choice(os.listdir(conf.seed_filefolder))[:-4]
        print('fileid', fileid)
        nums = len(os.listdir(conf.seed_filefolder))
        # target_fileid = nums + 1
        target_fileid = generation + 1
        if os.path.exists(os.path.join(conf.seed_filefolder,str(fileid)+'.pem')):
            try:
                nezha_update_certs(conf.seed_filefolder, str(fileid)+'.pem', conf.openssl_root, conf.openssl_leaf, str(target_fileid)+'.pem')
            except:
               continue
            if (os.path.exists(os.path.join(conf.seed_filefolder,str(target_fileid)+'.pem'))):
                generation += 1
                '''
                Collect results and simplify it here
                '''
                pattern = get_pattern(target_fileid)

                
                '''
                If it is a new pattern: if not, delete the new file.
                '''
                if pattern in GlobalState:
                    os.system('rm -rf ' + os.path.join(conf.seed_filefolder,str(target_fileid)+'.pem'))
                    os.system('rm -rf ' + os.path.join(conf.openssl_root,str(target_fileid)+'.pem'))
                    os.system('rm -rf ' + os.path.join(conf.openssl_leaf,str(target_fileid)+'.pem'))
                    os.system('rm -rf ' + os.path.join(conf.HOME_DIR+'utils/nss_seeds/',str(target_fileid)))
                    libs = ['openssl', 'polarssl', 'matrixssl', 'gnutls', 'nss']
                    for idx in range(len(libs)):
                        lib = libs[idx]
                        pem_name = str(target_fileid)+ '_' + lib + '.txt'
                        res_path = os.path.join(conf.test_results_path,pem_name)
                        os.system('rm -rf ' + res_path)
                else:
                    GlobalState.append(pattern)
                    os.system("sh scripts/batch_exec.sh "+str(target_fileid)+'.pem') #collect coverage
                    cov_restat(fileid,target_fileid,cov_stat)
                    print('---access new pattern---')




