
HOME_DIR ='...'
input_cert_path = HOME_DIR+'utils/corpus/' #corpus folder 
seed_filefolder = HOME_DIR+'utils/seeds/' #seed_certificate folder
ca_cert_path = HOME_DIR+'utils/rootCA.pem' #ca_path


##modify_log&& stat file path ####
modify_log_path = HOME_DIR +'utils/stats/mod_log.json'#log file that records the modification log 
file_cov_log = HOME_DIR + 'utils/stats/file_cov.json'#log file that records the coverage of file
cov_stat_log = HOME_DIR + 'utils/stats/cov_stat.json'#log file that records the information of coverage information 
openssl_root = HOME_DIR+'utils/root/'
openssl_leaf = HOME_DIR+'utils/leaf/'
cov_results_path = HOME_DIR + 'utils/cov/' #filefolder that contains the coverage

##on_the_fly_testing ##
test_results_path = HOME_DIR + 'utils/results/'
unconsis_folder = HOME_DIR + 'utils/unconsis/'#filefolder that contains the files that trigger the difference among implementations
unconsis_seed_path = unconsis_folder +'seeds/'
unconsis_root_path = unconsis_folder +'root/'
unconsis_leaf_path = unconsis_folder +'leaf/'

##strategy2
extension_corpus = HOME_DIR +'utils/extension_corpus/'
extension_json = HOME_DIR + 'utils/stats/corpus.json'




