import pandas as pd
import mucert_util
import os
import shutil
from OpenSSL import crypto
from datetime import datetime,timedelta
import conf
import sys

# add ver.1
def extension_init(filefolder):
    extensions = {}
    filelists = os.listdir(filefolder)

    extensions['extension'] = []
    for file in filelists:
        fileid = '.'.join(file.split('.')[:-1])

        pick_cert = mucert_util.load_file(os.path.join(conf.extension_corpus,fileid+'.pem'))[0]
        try:
            pick_cert.get_extension(0)
            extensions['extension'].append(fileid)
        except:
            pass

    mucert_util.dump_json(extensions,conf.extension_json)


def seed_stat_init(filefolder):
    file_cov={}
    cov_stat={}
    filelists = os.listdir(filefolder)
    for file in filelists:
        fileid = file.split('.')[0]
        (line_cov,branch_cov) = mucert_util.get_cov(os.path.join(filefolder,file))
        cov_key = str((line_cov,branch_cov))
        if cov_key in cov_stat.keys():
            cov_stat[cov_key]['cnt'] += 1
            cov_stat[cov_key]['fileids'].append(fileid)
        else:
            cov_stat[cov_key] = {}
            cov_stat[cov_key]['transfer_list'] = {}
            cov_stat[cov_key]['cnt'] = 1
            cov_stat[cov_key]['mod_cnt'] = 0
            cov_stat[cov_key]['fileids'] =list( [fileid])
        file_cov[fileid] = cov_key
    mucert_util.dump_json(file_cov,conf.file_cov_log)
    mucert_util.dump_json(cov_stat,conf.cov_stat_log)


def seed_func_stat_init(filefolder):
    file_cov = {}
    cov_stat ={}
    func_cov_code={}
    filelists = os.listdir(filefolder)
    for file in filelists:
        fileid = file.split('.')[0]
        func_set = mucert_util.get_func_set(os.path.join(filefolder,file))
        empty_set = set([])  # used to compare difference set
        func_len = str(len(func_set))
        func_code = func_len + '_0'
        cov_code = func_code
        if func_code not in func_cov_code.keys():
            func_cov_code[func_code] = list(func_set)
            file_cov[fileid] = func_code
        else:
            max_iter = len(func_cov_code.keys())
            for iter_num in range(max_iter):
                cov_code = func_len + '_' + str(iter_num)
                if cov_code in func_cov_code.keys():
                    func_set_0 = set(func_cov_code[cov_code])
                    if func_set.difference(func_set_0) == empty_set and func_set_0.difference(func_set) == empty_set:
                        file_cov[fileid] = cov_code
                        break
                else:
                    func_cov_code[cov_code] = list(func_set)
                    file_cov[fileid] = cov_code
                    break
        if func_code in cov_stat.keys():
            cov_stat[func_code]['cnt'] += 1
            cov_stat[func_code]['fileids'].append(fileid)
        else:
            cov_stat[func_code] = {}
            cov_stat[func_code]['transfer_list'] = {}
            cov_stat[func_code]['cnt'] = 1
            cov_stat[func_code]['mod_cnt'] = 0
            cov_stat[func_code]['fileids'] =list( [fileid])
    mucert_util.dump_json(file_cov, conf.file_cov_log)
    mucert_util.dump_json(cov_stat, conf.cov_stat_log)
    #mucert_util.dump_json(func_cov_code,conf.func_encoder_log)


def func_seed_stat(file_cov):
    cov_stat = {}
    for fileid in file_cov.keys():
        func_code = file_cov[fileid]
        if func_code in cov_stat.keys():
            cov_stat[func_code]['cnt'] += 1
            cov_stat[func_code]['fileids'].append(fileid)
        else:
            cov_stat[func_code] = {}
            cov_stat[func_code]['transfer_list'] = {}
            cov_stat[func_code]['cnt'] = 1
            cov_stat[func_code]['mod_cnt'] = 0
            cov_stat[func_code]['fileids'] =list( [fileid])
    mucert_util.dump_json(cov_stat, '/home/juliazhu/Documents/ssl_on_the_fly/stats/line/cov_stat_line.json')


if __name__ == '__main__':
     cov_folder = sys.argv[1] ##cov_folder
     seed_stat_init (cov_folder)

     extension_folder = conf.extension_corpus       # add ver.1
     extension_init(extension_folder)               # add ver.1









