import csv
import inspect
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import traceback

import fire
import requests
import tldextract
from loguru import logger
from termcolor import cprint
import os


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
        # cmd = ""
        print("get system type error")
        exit(1)


def isexist(filepath):
    if os.path.exists(filepath):
        return True
    else:
        logger.error(f'[-] {filepath} not found!')
        return False


@logger.catch
def getips(ipstr_list):
    ipstr_list = list(set(ipstr_list))
    ips_set = set()
    regx = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    for i in ipstr_list:
        if i:
            try:
                ip = re.findall(regx, i)[0]
                ips_set.add(ip)
            except Exception as e:
                logger.error(f'wentidata:{i}')
                logger.exception(str(e))
    logger.info(f'[+] ip number：{len(ips_set)}')
    return list(ips_set)


def whether_update(file):
    modify_time = os.path.getmtime(file)
    if time.time() - modify_time > 86400 * 5:
        return True
    else:
        return False


def checkport(port):
    if port < 1024 or 65535 < port:
        return False
    if 'win32' == sys.platform:
        cmd = 'netstat -aon|findstr ":%s "' % port
    elif 'linux' == sys.platform:
        cmd = 'netstat -aon|grep ":%s "' % port
    else:
        logger.error('Unsupported system type %s' % sys.platform)
        return False
    with os.popen(cmd, 'r') as f:
        if '' != f.read():
            return True
        else:
            logger.error('Port %s is not open' % port)
            return False


@logger.catch
def __subprocess(cmd):
    try:
        out_temp = tempfile.TemporaryFile(mode='w+b')
        fileno = out_temp.fileno()
        p = subprocess.Popen(cmd, shell=True, stdout=fileno, stderr=fileno)
        p.wait()
        out_temp.seek(0)
        rt = out_temp.read()
        rt_list = rt.strip().split('\n')
    except Exception as e:
        logger.error(traceback.format_exc())
    finally:
        if out_temp:
            out_temp.close()

    return rt_list


@logger.catch
def __subprocess1(cmd, timeout=None):
    if isinstance(cmd, str):
        cmd = cmd.split(' ')
    elif isinstance(cmd, list):
        cmd = cmd
    else:
        logger.error(f'[-] cmd type error,cmd should be a string or list: {cmd}')
        return
    try:
        p = subprocess.Popen(cmd, shell=True)
        if timeout:
            p.wait(timeout=timeout)
        else:
            p.wait()
    except Exception as e:
        logger.error(traceback.format_exc())
        # print(traceback.format_exc())
    finally:
        f_name = inspect.getframeinfo(inspect.currentframe().f_back)[2]
        logger.info(f'{f_name} finished.')


@logger.catch
def __subprocess2(cmd):
    if isinstance(cmd, str):
        cmd = cmd.split(' ')
    elif isinstance(cmd, list):
        cmd = cmd
    else:
        logger.error(f'[-] cmd type error,cmd should be a string or list: {cmd}')
        return
    lines = []
    try:

        out_temp = tempfile.SpooledTemporaryFile(max_size=10 * 1000, mode='w+b')
        fileno = out_temp.fileno()
        obj = subprocess.Popen(cmd, stdout=fileno, stderr=fileno, shell=True)
        obj.wait()
        out_temp.seek(0)
        lines = out_temp.readlines()

    except Exception as e:
        logger.error(traceback.format_exc())
    finally:
        if out_temp:
            out_temp.close()
    return lines


@logger.catch
def request0(req_json):
    proxies = {
        'http': 'http://127.0.0.1:7777',
        'https': 'http://127.0.0.1:7777',
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"}
    method0 = req_json['method']
    urls0 = req_json['url']
    headers0 = json.loads(req_json['headers']) if str(
        req_json['headers']).strip() != "" else headers if "headers" in req_json.keys() else ""
    data0 = req_json['data'] if "data" in req_json.keys() else ""
    try:
        if (method0 == 'GET'):
            a = requests.get(urls0, headers=headers0, proxies=proxies, timeout=30, verify=False)

        elif (method0 == 'POST'):
            a = requests.post(urls0, headers=headers0, data=data0, proxies=proxies, timeout=30, verify=False)

    except:
        logger.exception(f'[-] {urls0} request failed!')
        logger.error(f"[-] {req_json['url']} send to xray failed!")
        print(f"[-] {req_json['url']} send to xray failed!")
        pass


@logger.catch
def webmanager(domain=None, url=None, urlsfile=None, date="2022-09-02-00-01-39"):
    suffix = get_system()
    root = os.getcwd()
    pwd_and_file = os.path.abspath(__file__)
    pwd = os.path.dirname(pwd_and_file)

    grader_father = os.path.abspath(os.path.dirname(pwd_and_file) + os.path.sep + "../..")
    logger.info('-' * 10 + f'start {__file__}' + '-' * 10)

    vulscan_log_folder = f"result/{date}/vulscan_log"
    if os.path.exists(vulscan_log_folder) is False:
        os.makedirs(vulscan_log_folder)

    if domain and urlsfile is None and url is None:
        urlsfile = f"result/{date}/{domain}.subdomains.with.http.txt"
        output_filename_prefix = domain
    elif domain is None and urlsfile and url is None:
        output_filename_prefix = date
        urlsfile = urlsfile
    elif domain is None and urlsfile is None and url:
        subdomain_tuple = tldextract.extract(url)
        output_filename_prefix = '.'.join(part for part in subdomain_tuple if part).replace('.', '_')
        urlsfile = f"temp.{sys._getframe().f_code.co_name}.txt"
        with open(urlsfile, "w", encoding="utf-8") as f:
            f.write(url)

    @logger.catch
    def nuclei(urlsfile=urlsfile):
        '''
        nuclei 2.6.5
        结果输出目录 {vulscan_log_folder}/{sys._getframe().f_code.co_name}_log
        :return:
        '''
        logger.info('-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)

        # 更新poc库
        if os.path.exists(f"{pwd}/nuclei/pocdata") is False:
            os.makedirs(f"{pwd}/nuclei/pocdata")
        if whether_update(f"{pwd}/nuclei/pocdata"):
            cmdstr = pwd + f"/nuclei/nuclei{suffix} -silent -ut -ud {pwd}/nuclei/pocdata"
            logger.info(f"[+] command:{cmdstr}")
            os.system(cmdstr)
            logger.info(f'[+] {sys._getframe().f_code.co_name} update finished!')
        output_folder = f"{vulscan_log_folder}/{sys._getframe().f_code.co_name}_log"
        if os.path.exists(output_folder) is False:
            os.makedirs(output_folder)

        # -as, -automatic-scan         automatic web scan using wappalyzer technology detection to tags mapping
        cmdstr = f'{pwd}/nuclei/nuclei{suffix}  -l {urlsfile} -t {pwd}/nuclei/pocdata ' \
                 f'-automatic-scan -s low,medium,high,critical,unknown -no-color -rate-limit 500 -bulk-size 250 -concurrency 250 ' \
                 f'-silent -stats -si 10 -retries 2 -me {output_folder}'
        logger.info(f"[+] command:{cmdstr}")
        __subprocess1(cmdstr, timeout=None)

    # result/{date}/{domain}.subdomains_with_http.txt result/{date}/{domain}.subdomains_ips.txt
    @logger.catch
    def afrog(urlsfile=urlsfile):
        '''
        afrog 输出默认带一层reports  reports\E:\ccode\python\006_lunzi\core\tools\vulscan\vulweb.com.afrog.html:
        输出目录 reports/{domain}.afrog.html
        :return:
        '''
        logger.info('-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
        # 更新漏洞库，5天查一次更新一次
        try:
            if whether_update(f"{os.path.expanduser('~')}/afrog-pocs"):
                cmdstr = pwd + f'/afrog/afrog{suffix} --up'
                logger.info(f"[+] command:{cmdstr}")
                os.system(cmdstr)
                logger.info(f'[+] {sys._getframe().f_code.co_name} update finished!')
        except Exception as e:
            logger.exception(e)
            logger.error('afrog 更新失败')
        output_folder = f"{vulscan_log_folder}/{sys._getframe().f_code.co_name}_log"
        if os.path.exists(output_folder) is False:
            os.makedirs(output_folder)
        # cmd = pwd + f'/afrog/afrog{suffix} -T result/{date}/{domain}.subdomains_with_http.txt -o result/{date}/afrog_log/{domain}.afrog.html'
        cmdstr = f'{pwd}/afrog/afrog{suffix} -T {urlsfile} -o {output_filename_prefix}.{sys._getframe().f_code.co_name}.html'
        logger.info(f"[+] command:{cmdstr}")
        __subprocess1(cmdstr, timeout=None)

        if isexist(f"reports/{output_filename_prefix}.{sys._getframe().f_code.co_name}.html"):
            shutil.move(f"reports/{output_filename_prefix}.{sys._getframe().f_code.co_name}.html", output_folder)

    @logger.catch
    def vulmap(url=url, urlsfile=urlsfile):
        '''
        vulmap v0.9 可对 webapps 进行漏洞扫描, 并且具备漏洞利用功能, 目前支持的 webapps 包括 activemq, flink, shiro, solr,
        struts2, tomcat, unomi, drupal, elasticsearch, fastjson, jenkins, nexus, weblogic, jboss, spring, thinkphp
        输出目录
        :return:
        '''

        logger.info('-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
        if url:
            cmdstr = f'python3 {pwd}/vulmap/vulmap.py -u {url} --output-text {vulscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.txt'
        elif urlsfile:
            cmdstr = f'python3 {pwd}/vulmap/vulmap.py -f {urlsfile} --output-text {vulscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.txt'
        else:
            logger.error("Please check urlsfile")
            return
        logger.info(f"[+] command:{cmdstr}")
        # os.system(cmdstr)timeout=7200
        __subprocess1(cmdstr, timeout=None)

    @logger.catch
    def xray1(file=None, mode='webscan'):
        '''
        xray 主动扫描
        xray 1.9.1
        '''
        cprint('-' * 10 + f'start {sys._getframe().f_code.co_name} ...' + '-' * 10, 'green')
        tool_name = '{pwd}/xray/xray{suffix}'
        ports_list = ['80', '443', '8080', '8009', '8443']

        if os.path.exists(tool_name) is False:
            cprint('-' * 10 + f'{tool_name} not found' + '-' * 10, 'red')
            return
        output_folder = f'{vulscan_log_folder}/xray_log'  # result/{date}/vulscan_log/xray_log
        if os.path.exists(output_folder) is False:
            os.makedirs(output_folder)

        if file is None:
            if mode == 'webscan':
                file = f"result/{date}/{domain}.subdomains.with.http.txt"
                with open(file, 'r', encoding='utf-8') as f:
                    for url in f.readlines():
                        if url.strip() != "":
                            # cmd = pwd + f'/xray/xray{suffix} {mode} --basic-crawler {url.strip()} --html-output result/{date}/xray_log/{domain}.xray.{mode}.html'
                            cmdstr = pwd + f'/xray/xray{suffix} {mode} --basic-crawler {url.strip()} --html-output {output_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.{mode}.html'
                            cprint(f"[+] command:{cmdstr}", 'green')
                            os.system(cmdstr)

            elif mode == 'servicescan':
                pass
                # 批量检查的 1.file 中的目标, 一行一个目标，带端口
                # ./xray servicescan --target-file 1.file
                cmd = pwd + f'/xray/xray{suffix} {mode} --target-file {file} --html-output {output_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.{mode}.html'
                cprint(f"[+] command:{cmd}", 'green')
                os.system(cmd)
            elif mode == 'x':
                pass
                file = f"result/{date}/{domain}.subdomains.ips.txt"
                with open(file, 'r', encoding='utf-8') as f:
                    for url in f.readlines():
                        if url.strip() != "":
                            cmdstr = pwd + f'/xray/xray{suffix} {mode} --target {url.strip()} -p "{",".join(ports_list)}"--html-output {output_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.{mode}.html'
                            cprint(f"[+] command:{cmdstr}", 'green')
                            os.system(cmdstr)
                            # __subprocess1(cmdstr, timeout=900)

    @logger.catch
    def xray():
        '''
        xray 1.9.1
        :return:
        '''
        logger.info('-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
        output_folder = f'{vulscan_log_folder}/xray_log'  # f"result/{date}/vulscan_log/xray_log"
        if os.path.exists(output_folder) is False:
            os.makedirs(output_folder)
        xray_out = f'{pwd}/result/{date}/vulscan_log/xray_log/{time.strftime("%Y-%m-%d_%H_%M_%S", time.localtime())}.html'
        xray_cmd = ["xray.exe", "webscan", "--listen", "127.0.0.1:7777", "--html-output", xray_out]
        logger.info(f"[+] xray: {xray_cmd}")
        tool_path = os.path.join(pwd, 'xray')
        xray_rsp = subprocess.Popen(xray_cmd, shell=True, cwd=tool_path)  # 不是有wait() 进行阻塞，否则就只监听没结果了
        time.sleep(5)

    @logger.catch
    def vscan(urlsfile=urlsfile):
        '''
        vscan v2.1 改自nabbu，进行端口扫描，端口指纹识别，和简单的端口服务爆破
        说白了也是一个web扫描，移植的naabu,在naabu的基础上添加了一些功能，当使用-top-ports的时候
        直接调用原生naabu只扫描端口不识别指纹，不进行其他附加工作，即使有web，但使用-p参数可以，
        输入可以是url可以是ip，如果是url则只进行web探测，bug点
        输出目录
        :return:
        '''
        logger.info('-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
        ports_str = "21,22,23,25,53,53,69,80,81,88,110,111,111,123,123,135,137,139,161,177,389,427,443,445,465,500,515," \
                    "520,523,548,623,626,636,873,902,1080,1099,1433,1434,1521,1604,1645,1701,1883,1900,2049,2181,2375," \
                    "2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379," \
                    "7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,11211,27017,33848," \
                    "37777,50000,50070,61616"
        ports_str = "21,22,80,81,445,1433,1521,3306,6379,3389,7001,8009,8080,8081,8443"
        if urlsfile:
            cmdstr = f'{pwd}/vscan/vscan{suffix} -l {urlsfile} -rate 150 -scan-all-ips -no-color -csv -o {vulscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.csv'
        else:
            logger.error("Please check urlsfile")
            return
        logger.info(f"[+] command:{cmdstr}")
        __subprocess1(cmdstr, timeout=None)

    # {domain}.subdomain_with_http.txt
    nuclei(urlsfile=urlsfile)
    afrog(urlsfile=urlsfile)
    vulmap(urlsfile=urlsfile)
    # to_xray()
    # 扫描敏感目录和弱口令爆破
    vscan(urlsfile=urlsfile)


@logger.catch
def hostmanager(domain=None, ip=None, ipfile=None, date="2022-09-02-00-01-39"):
    suffix = get_system()
    root = os.getcwd()
    pwd_and_file = os.path.abspath(__file__)
    pwd = os.path.dirname(pwd_and_file)
    grader_father = os.path.abspath(os.path.dirname(pwd_and_file) + os.path.sep + "../..")
    logger.info('-' * 10 + f'start {__file__}' + '-' * 10)
    vulscan_log_folder = f"result/{date}/vulscan_log"
    if os.path.exists(vulscan_log_folder) is False:
        os.makedirs(vulscan_log_folder)

    # 两种模式,三种情况
    if domain and ipfile is None and ip is None:
        ipfile = f"result/{date}/{domain}.subdomains.ips.txt"
        output_filename_prefix = domain
    elif domain is None and ipfile and ip is None:
        ipfile = ipfile
        output_filename_prefix = ip
    elif domain is None and ipfile is None and ip:
        ipfile = f"temp.{sys._getframe().f_code.co_name}.txt"
        output_filename_prefix = date
        with open(ipfile, "w", encoding="utf-8") as f:
            f.write(ip)

    @logger.catch
    def goon(ip=ip, ipfile=ipfile):
        '''
        goon v3.5 
        :return:
        '''
        logger.info('-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
        if ip:
            cmdstr = f'{pwd}\goon\goon{suffix} -ip {ip} -ofile {vulscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.txt'
        elif ipfile:
            cmdstr = f'{pwd}\goon\goon{suffix} -ifile {ipfile} -ofile {vulscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.txt'
        else:
            logger.error("Please check ip or ipfile")
            return
        logger.info(f"[+] command:{cmdstr}")
        __subprocess1(cmdstr, timeout=None)

    @logger.catch
    def SweetBabyScan(ip=ip, ipfile=ipfile):
        '''
        SweetBabyScan v0.1.0
        SbScanAmd64_false.exe -host 44.228.249.3 -p normal -wsh 150 -wsp 150 -is False -oe 1/xx.xlsx -ot 1/xx.txt
        输出目录
        :return:
        '''
        logger.info('-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
        ports_str = "21,22,23,25,53,53,69,80,81,88,110,111,111,123,123,135,137,139,161,177,389,427,443,445,465,500,515," \
                    "520,523,548,623,626,636,873,902,1080,1099,1433,1434,1521,1604,1645,1701,1883,1900,2049,2181,2375," \
                    "2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379," \
                    "7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,11211,27017,33848," \
                    "37777,50000,50070,61616"
        ports_str = "21,22,80,81,445,1433,1521,3306,6379,3389,7001,8009,8080,8081,8443"
        # -host 121.46.128.13 -p 80-443 -scan-all-ips -no-color -o 2.txt -rate 100
        if ip:
            cmdstr = f'{pwd}/SweetBabyScan/SweetBabyScan{suffix} -host {ip} -p normal -wsh 150 -wsp 150 -ot {vulscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.txt -oe {vulscan_log_folder}/{ip}.{sys._getframe().f_code.co_name}.xlsx'
        elif ipfile:
            cmdstr = f'{pwd}/SweetBabyScan/SweetBabyScan{suffix} -host {ipfile} -p normal -wsh 150 -wsp 150 -ot {vulscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.txt -oe {vulscan_log_folder}/{date}.{sys._getframe().f_code.co_name}.xlsx'
        else:
            logger.error("Please check ip or ipfile")
            return
        logger.info(f"[+] command:{cmdstr}")
        __subprocess1(cmdstr, timeout=None)

    @logger.catch
    def vscan(ip=ip, ipfile=ipfile):
        '''
        vscan v2.1
        :return:
        '''
        logger.info('-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
        ports_str = "21,22,23,25,53,53,69,80,81,88,110,111,111,123,123,135,137,139,161,177,389,427,443,445,465,500,515," \
                    "520,523,548,623,626,636,873,902,1080,1099,1433,1434,1521,1604,1645,1701,1883,1900,2049,2181,2375," \
                    "2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379," \
                    "7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,11211,27017,33848," \
                    "37777,50000,50070,61616"
        ports_str = "21,22,80,81,445,1433,1521,3306,6379,3389,7001,8009,8080,8081,8443"
        # -host 121.46.128.13 -p 80-443 -scan-all-ips -no-color -o 2.txt -rate 100
        if ip:
            cmdstr = f'{pwd}/vscan/vscan{suffix} -host  {ip} -p {ports_str} -rate 150 -scan-all-ips -no-color -csv -o {vulscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.csv'
        elif ipfile:
            cmdstr = f'{pwd}/vscan/vscan{suffix} -l {ipfile} -p {ports_str} -rate 150 -scan-all-ips -no-color -csv -o {vulscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.csv'
        else:
            logger.error("Please check ip or ipfile")
            return
        logger.info(f"[+] command:{cmdstr}")
        __subprocess1(cmdstr, timeout=None)

    goon(ip=ip, ipfile=ipfile)
    # 暂未使用，主要是会下载chromewin每次执行
    SweetBabyScan(ip=ip, ipfile=ipfile)
    vscan(ip=ip, ipfile=ipfile)


@logger.catch
def run(target=None, targets=None, mode='web', date=None):
    '''
    单模块使用支持web扫描，主机ip扫描
    两个模块都支持单ip or url 或者file扫描，暂不支持c段扫描

    usage:
        target is url
        python main.py --target xxx.com
        python main.py --targets urls.txt
        python main.py --target xxx.com  --mode web

        target is ip
        python main.py --target 1.1.1.1/1.1.1.1/24 --mode host
        python main.py --targets ips.txt  --mode host


    :param str  target:     One url or ip
    :param str  targets:    File path of file
    :param str  mode:       scan web or host
    :return:
    '''
    create_logfile()
    import datetime
    date1 = str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
    date = date if date else date1
    ip_or_url = target
    file = targets
    if mode == 'web':
        if ip_or_url and file is None:
            webmanager(domain=None, url=ip_or_url, urlsfile=None, date=date)
        elif file and ip_or_url is None:
            if os.path.exists(file):
                webmanager(domain=None, url=None, urlsfile=file, date=date)
            else:
                logger.error(f'{file} not found!')
        else:
            logger.error("Please check that the parameters are correct.")
    elif mode == "host":
        if ip_or_url and file is None:
            hostmanager(domain=None, ip=ip_or_url, ipfile=None, date=date)
        elif file and ip_or_url is None:
            if os.path.exists(file):
                hostmanager(domain=None, ip=None, ipfile=file, date=date)
            else:
                logger.error(f'{file} not found!')
        else:
            logger.error("Please check that the parameters are correct.")
    else:
        logger.error("Please check that the parameters are correct.")


if __name__ == '__main__':
    fire.Fire(run)
