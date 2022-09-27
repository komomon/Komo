import inspect
import json
import os
import shutil
import subprocess
import sys
import dns
import fire
from loguru import logger


def create_logfile():
    if os.path.exists(f'{os.getcwd()}/log') is False:
        os.makedirs(f'{os.getcwd()}/log')
    logger.add(sink='log/runtime.log', level='INFO', encoding='utf-8')
    logger.add(sink='log/error.log', level='ERROR', encoding='utf-8')


def get_system():

    platform = sys.platform
    if platform == 'win32':
        suffix = ".exe"
        return suffix
    elif "linux" in platform:
        return ""
    else:
        print("get system type error")
        exit(1)


@logger.catch
def manager(domain=None, ip=None, ipfile=None, date="2022-09-02-00-01-39"):
    suffix = get_system()
    root = os.getcwd()
    pwd_and_file = os.path.abspath(__file__)
    pwd = os.path.dirname(pwd_and_file)

    grader_father = os.path.abspath(
        os.path.dirname(pwd_and_file) + os.path.sep + "../..")

    portscan_log_folder = f"result/{date}/portscan_log"
    if os.path.exists(portscan_log_folder) is False:
        os.makedirs(portscan_log_folder)

    if domain and ip is None and ipfile is None:
        ipfile = f'result/{date}/{domain}.subdomains.ips.txt'
        output_filename_prefix = domain
    elif ipfile and domain is None and ip is None:
        ipfile = ipfile
        output_filename_prefix = date
    elif ip and domain is None and ipfile is None:
        output_filename_prefix = ip
        ipfile = f"temp.ips.txt"
        with open(ipfile, "w", encoding="utf-8") as f:
            f.write(ip)
    else:
        logger.error("[-] Please --domain or --ip or --ipfile")

    @logger.catch
    def naabu(ip=ip, ipfile=ipfile):
        '''
        naabu 2.1.0
        :return:
        '''
        logger.info(
            '-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
        ports_str = "22,80,1433,1521,3389,8009,8080,8443"
        ports_str = "21,22,23,25,53,53,69,80,81,88,110,111,111,123,123,135,137,139,161,177,389,427,443,445,465,500,515," \
                    "520,523,548,623,626,636,873,902,1080,1099,1433,1434,1521,1604,1645,1701,1883,1900,2049,2181,2375," \
                    "2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379," \
                    "7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,11211,27017,33848," \
                    "37777,50000,50070,61616"
        # print(domain,ip,ips,ipfile)
        outputfile = f'{portscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.txt'
        cmdstr = f'{pwd}/naabu/naabu{suffix} -source-ip 8.8.8.8:22 -rate 150 -top-ports 100 -silent -no-color -list {ipfile} -o {outputfile}'
        # naabu -list hosts.txt -p - 扫描全部  -exclude-cdn 跳过cdn检测，cdn只检查80 443
        # cmd = pwd + f'/naabu{suffix} -p "{ports_str}" -silent -no-color -scan-all-ips -list result/{date}/{domain}.final.subdomains.txt -o {portscan_log_folder}/{domain}.{sys._getframe().f_code.co_name}.txt'
        # nmap 常见100个端口 -scan-all-ips
        # cmdstr = f'{pwd}/naabu{suffix} -top-ports 100 -silent -no-color -list result/{date}/{domain}.final.subdomains.txt -o {portscan_log_folder}/{domain}.{sys._getframe().f_code.co_name}.txt'
        logger.info(f"[+] command:{cmdstr}")
        os.system(cmdstr)
        logger.info(f'[+] naabu finished,outputfile:{outputfile}')

    @logger.catch
    def nmaps(ip=ip, ipfile=ipfile):
        '''
        nmaps 1.0 2020
        :return:
        '''
        logger.info(
            '-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
        ports_str = "22,80,1433,1521,3389,8009,8080,8443"
        ports_str = "21,22,23,25,53,53,69,80,81,88,110,111,111,123,123,135,137,139,161,177,389,427,443,445,465,500,515," \
                    "520,523,548,623,626,636,873,902,1080,1099,1433,1434,1521,1604,1645,1701,1883,1900,2049,2181,2375," \
                    "2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379," \
                    "7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,11211,27017,33848," \
                    "37777,50000,50070,61616"
        # print(domain,ip,ips,ipfile)-host 44.228.249.3 -top-ports -nC -source-ip 8.8.8.8 -o 22.txt
        # -iL 1.txt -top-ports -nC -source-ip 8.8.8.8 -o 22.txt -silent -retries 2
        if domain and ip is None and ipfile is None:
            file = f'result/{date}/{domain}.subdomains.ips.txt'
            outputfile = f'{portscan_log_folder}/{domain}.{sys._getframe().f_code.co_name}.txt'
            cmdstr = f'{pwd}/nmaps/nmaps{suffix} -top-ports 100 -silent -source-ip 8.8.8.8 -retries 2 -nC -iL {file} -o {outputfile}'
        elif ipfile and domain is None and ip is None:
            file = ipfile
            outputfile = f'{portscan_log_folder}/{date}.{sys._getframe().f_code.co_name}.txt'
            cmdstr = f'{pwd}/nmaps/nmaps{suffix} -top-ports 100 -silent -source-ip 8.8.8.8 -retries 2 -nC -iL {file} -o {outputfile}'
        else:
            logger.error("[-] Please --domain or --ips")
            exit(1)
        logger.info(f"[+] command:{cmdstr}")
        os.system(cmdstr)

    naabu(ip=None, ipfile=ipfile)
    # nmaps(ips=None,ipfile=ipfile)


@logger.catch
def run(ip=None, ips=None, ipfile=None, date=None):
    '''
    usage:

        python main.py --ip 127.0.0.1
        python main.py --ips ips.txt

    :param str  url:     One ip
    :param str  urlfile:    File path of ipfile per line
    :return:
    '''
    create_logfile()
    import datetime
    date1 = str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
    date = date if date else date1
    if ip and ipfile is None:
        manager(domain=None, ip=ip, ipfile=None, date=date)
    elif ipfile and ip is None:
        if os.path.exists(ips):
            manager(domain=None, ip=None, ipfile=ipfile, date=date)
        else:
            logger.error(f'{ips} not found!')
    else:
        logger.error(
            "Please check --ip or --ips\nCheck that the parameters are correct.")


if __name__ == '__main__':
    fire.Fire(run)
