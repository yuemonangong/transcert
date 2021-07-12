import pandas as pd
import mucert_util
import os
import shutil
from OpenSSL import crypto
from datetime import datetime,timedelta
import conf
import sys

def seeds_process(seed_folder):
    files = os.listdir(seed_folder)
    i = 0
    for f in files:
        inpath = os.path.join(seed_folder, f)
        outpath = os.path.join(seed_folder, 'new' + f)
        try:
            mucert_util.recycle_cert(inpath, outpath, conf.ca_cert_path, True)
            os.remove(inpath)
        except:
            print('failed', f)
        i += 1
        if i%100 == 0:
            print(i)


if __name__ == '__main__':
    seed_folder = conf.seed_filefolder
    seeds_process(seed_folder)
