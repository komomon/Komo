import csv
import hashlib
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
    # global suffix
    platform = sys.platform
    if platform == 'win32':
        suffix = ".exe"
        return suffix
    elif "linux" in platform:
        return ""
    else:
        print("get system type error")
        exit(1)


# 进度记录,基于json
def progress_record_old(date=None, target=None, module=None, value=None, finished=False):
    logfile = f"result/{date}/log.json"
    if os.path.exists(logfile) is False:
        shutil.copy("config/log_template.json", f"result/{date}/log.json")
    with open(logfile, "r", encoding="utf-8") as f1:
        log_json = json.loads(f1.read())
    if finished is False:
        # 读取log.json 如果是false则扫描，是true则跳过
        if log_json[module] is False:
            return False
        elif log_json[module] is True:  # 即log_json[module] 为true的情况
            return True
    elif finished is True:
        log_json[module] = True
        with open(logfile, "w", encoding="utf-8") as f:
            f.write(json.dumps(log_json))
        return True


# 进度记录,基于json
def progress_record(date=None, target=None, module="portscan", value=None, finished=False):
    target_log = {"domain": False,
                  "emailcollect": False,
                  "survivaldetect": False,
                  "finger": False,
                  "portscan": False,
                  "sensitiveinfo": {
                      "scanned_targets": []
                  },
                  "vulscan": {
                      "webattack": False,
                      "hostattack": False
                  }
                  }
    logfile = f"result/{date}/log.json"
    if os.path.exists(logfile) is False:
        shutil.copy("config/log_template.json", f"result/{date}/log.json")
    with open(logfile, "r", encoding="utf-8") as f1:
        log_json = json.loads(f1.read())
    if finished is False:
        # 读取log.json 如果是false则扫描，是true则跳过
        if target not in dict(log_json["target_log"]).keys():
            log_json["target_log"][target] = target_log
            with open(logfile, "w", encoding="utf-8") as f:
                f.write(json.dumps(log_json))
            return False
        else:
            if log_json["target_log"][target][module] is False:
                return False
            # elif log_json["target_log"][target][module] is True:  # 即log_json["target_log"][target][module] 为true的情况
            else:
                return True
    elif finished is True:
        # 如果已经存在对应目标的target_log 字典,则直接修改即可，否则添加target_log 并将domain键值设为true
        # if target not in dict(log_json["target_log"]).keys():
        if target in dict(log_json["target_log"]).keys():
            log_json["target_log"][target][module] = True
        else:
            target_log[module] = True
            log_json["target_log"][target] = target_log
        with open(logfile, "w", encoding="utf-8") as f:
            f.write(json.dumps(log_json))
        return True


# def manager(domain=None,ip=None,ips=None,ipfile=None,date="2022-09-02-00-01-39"):
@logger.catch
def manager(domain=None, ip=None, ipfile=None, date="2022-09-02-00-01-39"):
    logger.info('\n' + '<' * 18 + f'start {__file__}' + '>' * 18)
    suffix = get_system()
    root = os.getcwd()
    pwd_and_file = os.path.abspath(__file__)
    pwd = os.path.dirname(pwd_and_file)  # E:\ccode\python\006_lunzi\core\tools\domain

    # 获取当前目录的前三级目录，即到domain目录下，来寻找exe domain目录下
    grader_father = os.path.abspath(os.path.dirname(pwd_and_file) + os.path.sep + "../..")
    # print(grader_father) # E:\ccode\python\006_lunzi\core
    # 创建存储工具扫描结果的文件夹
    portscan_log_folder = f"result/{date}/portscan_log"
    if os.path.exists(portscan_log_folder) is False:
        os.makedirs(portscan_log_folder)

    # 三种模式
    if domain and ip is None and ipfile is None:
        # ipfile = f'result/{date}/{domain}.subdomains.ips.txt'
        ipfile = f"result/{date}/{domain}.nocdn.ips.txt"
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
        exit(1)

    # naabu 可以对域名反查ip然后端口扫描，也可以对ips进行端口扫描
    # 目前实现对ipfile和子域名的扫描
    @logger.catch
    def naabu(ip=ip, ipfile=ipfile):
        '''
        naabu 2.1.0
        :return:
        '''
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)
        ports_str = "22,80,1433,1521,3389,8009,8080,8443"
        ports_str = "21,22,23,25,53,53,69,80,81,88,110,111,111,123,123,135,137,139,161,177,389,427,443,445,465,500,515," \
                    "520,523,548,623,626,636,873,902,1080,1099,1433,1434,1521,1604,1645,1701,1883,1900,2049,2181,2375," \
                    "2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379," \
                    "7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,11211,27017,33848," \
                    "37777,50000,50070,61616"
        # print(domain,ip,ips,ipfile)
        # toolname =
        output_filename = f'{portscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}'
        # -exclude-cdn, -ec	  skip full port scans for CDN's (only checks for 80,443)
        # -proxy string		 socks5 proxy (ip[:port] / fqdn[:port]
        # -proxy-auth string		socks5 proxy authentication (username:password)
        cmdstr = f'{pwd}/naabu/naabu{suffix} -source-ip 8.8.8.8:22 -rate 600 -top-ports 1000 -silent -no-color -list {ipfile} -csv -o {output_filename}.csv'
        # naabu -list hosts.txt -p - 扫描全部  -exclude-cdn 跳过cdn检测，cdn只检查80 443
        # cmd = pwd + f'/naabu{suffix} -p "{ports_str}" -silent -no-color -scan-all-ips -list result/{date}/{domain}.final.subdomains.txt -o {portscan_log_folder}/{domain}.{sys._getframe().f_code.co_name}.txt'
        # nmap 常见100个端口 -scan-all-ips
        # cmdstr = f'{pwd}/naabu{suffix} -top-ports 100 -silent -no-color -list result/{date}/{domain}.final.subdomains.txt -o {portscan_log_folder}/{domain}.{sys._getframe().f_code.co_name}.txt'
        logger.info(f"[+] command:{cmdstr}")
        os.system(cmdstr)
        logger.info(f'[+] {sys._getframe().f_code.co_name} finished,outputfile:{output_filename}.csv')
        with open(f"{output_filename}.csv", "r") as f1:
            reader = csv.reader(f1)
            head = next(reader)
            with open(f"result/{date}/{output_filename_prefix}.ports.txt", "w") as f2:
                for row in reader:
                    # baidu.com:8080  192.168.1.1:53
                    lline = f"{row[0]}:{row[2]}" if row[0] else f"{row[1]}:{row[2]}"
                    f2.write(lline + '\n')

    @logger.catch
    def TxPortMap(ip=ip, ipfile=ipfile):
        '''
        TxPortMap 20211210
        :return:
        '''
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)
        ports_str = "22,80,1433,1521,3389,8009,8080,8443"
        ports_str = "21,22,23,25,53,53,69,80,81,88,110,111,111,123,123,135,137,139,161,177,389,427,443,445,465,500,515," \
                    "520,523,548,623,626,636,873,902,1080,1099,1433,1434,1521,1604,1645,1701,1883,1900,2049,2181,2375," \
                    "2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379," \
                    "7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,11211,27017,33848," \
                    "37777,50000,50070,61616"
        outputfile = f'{portscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.txt'
        # cmdstr = f'{pwd}/TxPortMap/TxPortMap{suffix} -p {ports_str} -nbtscan -l {ipfile} -o {outputfile}'
        cmdstr = f'{pwd}/TxPortMap/TxPortMap{suffix} -t1000 -nbtscan -ep 25,110 -l {ipfile} -o {outputfile}'
        logger.info(f"[+] command:{cmdstr}")
        os.system(cmdstr)
        logger.info(f'[+] {sys._getframe().f_code.co_name} finished,outputfile:{outputfile}')

    # win不可用先剔除
    @logger.catch
    def dismap(ip=ip, ipfile=ipfile):
        '''
        dismap 0.4
        :return:
        '''
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)
        ports_str = "22,80,1433,1521,3389,8009,8080,8443"
        ports_str = "21,22,23,25,53,53,69,80,81,88,110,111,111,123,123,135,137,139,161,177,389,427,443,445,465,500,515," \
                    "520,523,548,623,626,636,873,902,1080,1099,1433,1434,1521,1604,1645,1701,1883,1900,2049,2181,2375," \
                    "2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379," \
                    "7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,11211,27017,33848," \
                    "37777,50000,50070,61616"
        # print(domain,ip,ips,ipfile)
        outputfile = f'{portscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.txt'
        cmdstr = f'{pwd}/dismap/dismap{suffix} --file {ipfile} --np -p {ports_str} -o {outputfile}'
        logger.info(f"[+] command:{cmdstr}")
        os.system(cmdstr)
        logger.info(f'[+] {sys._getframe().f_code.co_name} finished,outputfile:{outputfile}')

    # 写好了，暂不调用了，这个项目使用了nmap的库，并对端口进行指纹识别，同时也借用了naabu的思路，但是是2020年的，同时使用的是connect连接，不是syn
    @logger.catch
    def nmaps(ip=ip, ipfile=ipfile):
        '''
        nmaps 1.0 2020
        :return:
        '''
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)
        ports_str = "22,80,1433,1521,3389,8009,8080,8443"
        ports_str = "21,22,23,25,53,53,69,80,81,88,110,111,111,123,123,135,137,139,161,177,389,427,443,445,465,500,515," \
                    "520,523,548,623,626,636,873,902,1080,1099,1433,1434,1521,1604,1645,1701,1883,1900,2049,2181,2375," \
                    "2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379," \
                    "7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,11211,27017,33848," \
                    "37777,50000,50070,61616"
        # print(domain,ip,ips,ipfile)-host 44.228.249.3 -top-ports -nC -source-ip 8.8.8.8 -o 22.txt
        # -iL 1.txt -top-ports -nC -source-ip 8.8.8.8 -o 22.txt -silent -retries 2
        outputfile = f'{portscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.txt'
        cmdstr = f'{pwd}/nmaps/nmaps{suffix} -top-ports 100 -silent -source-ip 8.8.8.8 -retries 2 -nC -iL {ipfile} -o {outputfile}'
        logger.info(f"[+] command:{cmdstr}")
        os.system(cmdstr)
        logger.info(f'[+] {sys._getframe().f_code.co_name} finished,outputfile:{outputfile}')

    def run():
        target = domain if domain else hashlib.md5(bytes(date, encoding='utf-8')).hexdigest()
        if progress_record(date=date, target=target, module="portscan", finished=False) is False:
            naabu(ip=None, ipfile=ipfile)
            TxPortMap(ip=None, ipfile=ipfile)
            # nmaps(ip=None,ipfile=ipfile)
            # dismap(ip=None,ipfile=ipfile)
            progress_record(date=date, target=target, module="portscan", finished=True)

    run()


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
    # 后面吧ip 支持cidr,去掉ips参数
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
        logger.error("Please check --ip or --ips\nCheck that the parameters are correct.")


if __name__ == '__main__':
    fire.Fire(run)
    # http://testphp.vulnweb.com/vendor
    # manager(domain="vulnweb.com",ip=None,ips=None,date="2022-09-02-00-01-39")
    # manager(domain="tiqianle.com", ip=None, date="2022-09-02-00-01-39")
