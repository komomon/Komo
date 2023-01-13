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


# 进度记录,基于json
def progress_record(date=None, target=None, module=None, submodule=None, value=None, finished=False):
    logfile = f"result/{date}/log.json"
    if os.path.exists(logfile) is False:
        shutil.copy("config/log_template.json", f"result/{date}/log.json")
    with open(logfile, "r", encoding="utf-8") as f1:
        log_json = json.loads(f1.read())
    if finished is False:
        # 读取log.json 如果是false则扫描，是true则跳过
        if log_json[module][submodule] is False:
            return False
        elif log_json[module][submodule] is True:  # 即log_json[module] 为true的情况
            return True
    elif finished is True:
        log_json[module][submodule] = True
        with open(logfile, "w", encoding="utf-8") as f:
            f.write(json.dumps(log_json))
        return True


def isexist(filepath):
    if os.path.exists(filepath):
        return True
    else:
        logger.error(f'[-] {filepath} not found!')
        return False


# 获取ip并去重
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
    # iplist =
    logger.info(f'[+] ip number：{len(ips_set)}')
    return list(ips_set)


# 判断当前时间与上次修改时间的大小，如果差大于5天，则更新
def whether_update(file):
    if os.path.exists(file):
        modify_time = os.path.getmtime(file)
        time_difference = time.time() - modify_time
        if time_difference < 86400 or time_difference > 86400 * 5:
            return True
        else:
            return False
    else:
        os.makedirs(file)
        logger.info(f"[+] Create {file} success")
        return True


def checkport(port):
    if port < 1024 or 65535 < port:
        # privileged port
        # out of range
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


# 启用子进程执行外部shell命令
@logger.catch
def __subprocess(cmd):
    # 得到一个临时文件对象， 调用close后，此文件从磁盘删除
    out_temp = tempfile.TemporaryFile(mode='w+b')
    rt_list = []
    try:
        # 获取临时文件的文件号
        fileno = out_temp.fileno()
        # 执行外部shell命令， 输出结果存入临时文件中
        p = subprocess.Popen(cmd, shell=True, stdout=fileno, stderr=fileno)
        p.wait()
        # 从临时文件读出shell命令的输出结果
        out_temp.seek(0)
        rt = out_temp.read()
        # 以换行符拆分数据，并去掉换行符号存入列表
        rt_list = rt.strip().split('\n')
    except Exception as e:
        logger.error(traceback.format_exc())
        # print(traceback.format_exc())
    finally:
        if out_temp:
            out_temp.close()
    return rt_list


# 启用子进程执行外部shell命令,使用Popen函数，shell=False, linux下 goon，vscan vulmap afrog不支持Popen子线程执行，但是shell为False是可以的,但是支持run，window下可以使用Popen
# @logger.catch
def __subprocess1(cmd, timeout=None):
    # if isinstance(cmd, str):
    #     cmd = cmd.split(' ')
    # elif isinstance(cmd, list):
    #     cmd = cmd
    # else:
    #     logger.error(f'[-] cmd type error,cmd should be a string or list: {cmd}')
    #     return
    # 执行外部shell命令， 输出结果存入临时文件中
    p = subprocess.Popen(cmd, shell=True)
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired as e:
        logger.error(f"{cmd[0]} run {timeout}s, Timeout and Exit. Error:{e}")
        p.kill()
    except Exception as e:
        logger.error(traceback.format_exc())
        # print(traceback.format_exc())
    finally:
        f_name = inspect.getframeinfo(inspect.currentframe().f_back)[2]
        logger.info(f'{f_name} finished.')


# 启用子进程执行外部shell命令,使用subprocess.run函数，暂未使用
def __subprocess11(cmd, timeout=None, path=None):
    # if isinstance(cmd, str):
    #     cmd = cmd.split(' ')
    # elif isinstance(cmd, list):
    #     cmd = cmd
    # else:
    #     logger.error(f'[-] cmd type error,cmd should be a string or list: {cmd}')
    #     return
    try:
        p = subprocess.run(cmd, shell=True, timeout=int(timeout), cwd=path)
        # p = subprocess.run(cmd, shell=True, timeout=int(timeout), cwd=path, stdout=subprocess.PIPE)
    except subprocess.TimeoutExpired as e:
        logger.error(f"{cmd[0]} run {timeout}s, Timeout and Exit. Error:{e}")

    except Exception as e:
        logger.error(traceback.format_exc())
        # print(traceback.format_exc())
    finally:
        f_name = inspect.getframeinfo(inspect.currentframe().f_back)[2]
        logger.info(f'{f_name} finished.')


@logger.catch
def __subprocess2(cmd):
    # if isinstance(cmd, str):
    #     cmd = cmd.split(' ')
    # elif isinstance(cmd, list):
    #     cmd = cmd
    # else:
    #     logger.error(f'[-] cmd type error,cmd should be a string or list: {cmd}')
    #     return
    lines = []
    out_temp = tempfile.SpooledTemporaryFile(max_size=10 * 1000, mode='w+b')
    try:
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


# 暂时无函数调用发送http请求，目的将结果发给xray
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
            requests.get(urls0, headers=headers0, proxies=proxies, timeout=30, verify=False)
        elif (method0 == 'POST'):
            requests.post(urls0, headers=headers0, data=data0, proxies=proxies, timeout=30, verify=False)
    except:
        logger.exception(f'[-] {urls0} request failed!')
        logger.error(f"[-] {req_json['url']} send to xray failed!")
        print(f"[-] {req_json['url']} send to xray failed!")
        pass


# 对web进行扫描
@logger.catch
def webmanager(domain=None, url=None, urlsfile=None, date="2022-09-02-00-01-39"):
    logger.info('\n' + '<' * 18 + f'start {__file__}' + '>' * 18)
    suffix = get_system()
    root = os.getcwd()
    pwd_and_file = os.path.abspath(__file__)
    pwd = os.path.dirname(pwd_and_file)  # E:\ccode\python\006_lunzi\core\tools\vulscan
    # 获取当前目录的前三级目录，即到domain目录下，来寻找exe domain目录下
    grader_father = os.path.abspath(os.path.dirname(pwd_and_file) + os.path.sep + "../..")
    # 创建存储子域名工具扫描结果的文件夹
    vulscan_log_folder = f"result/{date}/vulscan_log"
    if os.path.exists(vulscan_log_folder) is False:
        os.makedirs(vulscan_log_folder)

    # 两种模式,三种情况
    if domain and urlsfile is None and url is None:
        urlsfile = f"result/{date}/{domain}.subdomains.with.http.txt"
        output_filename_prefix = domain
    elif domain is None and urlsfile and url is None:
        output_filename_prefix = date
        urlsfile = urlsfile
    elif domain is None and urlsfile is None and url:
        subdomain_tuple = tldextract.extract(url)
        output_filename_prefix = '.'.join(part for part in subdomain_tuple if part)  # www_baidu_com 127_0_0_1
        urlsfile = f"temp.{sys._getframe().f_code.co_name}.txt"
        with open(urlsfile, "w", encoding="utf-8") as f:
            f.write(url)

    @logger.catch
    def nuclei(urlsfile=urlsfile):
        '''
        nuclei 2.6.5
        linux下 nuclei 不支持Popen子线程执行不管shell参数为True还是False
        结果输出目录 {vulscan_log_folder}/{sys._getframe().f_code.co_name}_log
        :return:
        '''
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)

        # 更新poc库
        # if os.path.exists(f"{pwd}/nuclei/pocdata") is False:
        #     os.makedirs(f"{pwd}/nuclei/pocdata")
        if whether_update(f"{pwd}/nuclei/pocdata"):
            cmdstr = pwd + f"/nuclei/nuclei{suffix} -silent -ut -ud {pwd}/nuclei/pocdata"
            logger.info(f"[+] command:{cmdstr}")
            os.system(cmdstr)
            logger.info(f'[+] {sys._getframe().f_code.co_name} update finished!')
        # 创建nuclei_log目录，存储扫描结果，md报告
        output_folder = f"{vulscan_log_folder}/{sys._getframe().f_code.co_name}_log"
        if os.path.exists(output_folder) is False:
            os.makedirs(output_folder)

        # -as, -automatic-scan         automatic web scan using wappalyzer technology detection to tags mapping
        # -proxy-url http://192.168.1.1:8080
        cmdstr = f'{pwd}/nuclei/nuclei{suffix}  -l {urlsfile} -t {pwd}/nuclei/pocdata ' \
                 f'-automatic-scan -s low,medium,high,critical,unknown -no-color -rate-limit 200 -bulk-size 50 -concurrency 100 ' \
                 f'-silent -stats -si 10 -retries 2 -me {output_folder}'
        logger.info(f"[+] command:{cmdstr}")
        os.system(cmdstr)
        # __subprocess1(cmdstr, timeout=None)

    # result/{date}/{domain}.subdomains_with_http.txt result/{date}/{domain}.subdomains_ips.txt
    @logger.catch
    def afrog(urlsfile=urlsfile):
        '''
        afrog 输出默认带一层reports  reports\E:\ccode\python\006_lunzi\core\tools\vulscan\vulweb.com.afrog.html:
        输出目录 reports/{domain}.afrog.html
        :return:
        '''
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)
        # 更新漏洞库，5天查一次更新一次
        try:
            if whether_update(f"{os.path.expanduser('~')}/afrog-pocs"):
                cmdstr = f'{pwd}/afrog/afrog{suffix} --up'
                logger.info(f"[+] command:{cmdstr}")
                os.system(cmdstr)
                logger.info(f'[+] {sys._getframe().f_code.co_name} update finished!')
        except Exception as e:
            logger.exception(e)
            logger.error('afrog update afrog-pocs failed!')
        # 对url进行poc扫描，输出html的报告
        output_folder = f"{vulscan_log_folder}/{sys._getframe().f_code.co_name}_log"
        if os.path.exists(output_folder) is False:
            os.makedirs(output_folder)
        # cmd = pwd + f'/afrog/afrog{suffix} -T result/{date}/{domain}.subdomains_with_http.txt -o result/{date}/afrog_log/{domain}.afrog.html'
        cmdstr = f'{pwd}/afrog/afrog{suffix} -T {urlsfile} -o {output_filename_prefix}.{sys._getframe().f_code.co_name}.html'
        logger.info(f"[+] command:{cmdstr}")
        os.system(cmdstr)
        # __subprocess1(cmdstr, timeout=None)
        # 移动结果文件到对应目录下
        if isexist(f"reports/{output_filename_prefix}.{sys._getframe().f_code.co_name}.html"):
            shutil.move(f"reports/{output_filename_prefix}.{sys._getframe().f_code.co_name}.html", output_folder)

    # 目前只支持urls文件，单个url也是写入文件，然后工具从文件中读取
    @logger.catch
    def vulmap(url=url, urlsfile=urlsfile):
        '''
        vulmap v0.9 可对 webapps 进行漏洞扫描, 并且具备漏洞利用功能, 目前支持的 webapps 包括 activemq, flink, shiro, solr,
        struts2, tomcat, unomi, drupal, elasticsearch, fastjson, jenkins, nexus, weblogic, jboss, spring, thinkphp
        输出目录
        :return:
        '''
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)
        # 目前只支持urls文件，单个url也是写入文件，然后工具从文件中读取
        if url:
            cmdstr = f'python3 {pwd}/vulmap/vulmap.py -u {url} --output-text {vulscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.txt'
        elif urlsfile:
            cmdstr = f'python3 {pwd}/vulmap/vulmap.py -f {urlsfile} --output-text {vulscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.txt'
        else:
            logger.error("Please check urlsfile")
            return
        logger.info(f"[+] command:{cmdstr}")
        os.system(cmdstr)
        # os.system(cmdstr)timeout=7200
        # __subprocess1(cmdstr, timeout=None)

    # 暂时不用，未完成，主动行为 xray 主动扫描
    @logger.catch
    def xray1(file=None, mode='webscan'):
        '''
        xray 主动扫描
        xray 1.9.1
        '''
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)
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
            # 扫主机到时候在改改,需要加端口
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

    # 废弃，不过已经写好了，需要优化，为xray起监听用，但是为了更好看到结果，决定不在线程中起xray，单独console起xray便于观察结果，故废弃
    @logger.catch
    def xray():
        '''
        xray 1.9.1
        :return:
        '''
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)
        # pwd_and_file = os.path.abspath(__file__)
        # pwd = os.path.dirname(pwd_and_file)  # E:\ccode\python\006_lunzi\core\tools\domain

        # 对url进行poc扫描，输出html的报告
        output_folder = f'{vulscan_log_folder}/xray_log'  # f"result/{date}/vulscan_log/xray_log"
        if os.path.exists(output_folder) is False:
            os.makedirs(output_folder)
        xray_out = f'{pwd}/result/{date}/vulscan_log/xray_log/{time.strftime("%Y-%m-%d_%H_%M_%S", time.localtime())}.html'
        xray_cmd = ["xray.exe", "webscan", "--listen", "127.0.0.1:7777", "--html-output", xray_out]
        logger.info(f"[+] xray: {xray_cmd}")
        tool_path = os.path.join(pwd, 'xray')
        xray_rsp = subprocess.Popen(xray_cmd, shell=True, cwd=tool_path)  # 不是有wait() 进行阻塞，否则就只监听没结果了
        time.sleep(5)

    # 暂时先不用，发送到xray被动扫描 存在很多遗漏，以后有时间再细测
    def to_xray():
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)
        if checkport(7777) is False: return
        # 发送给xray的监听端口
        if isexist(f'result/{date}/{domain}.links.csv') is False: return
        with open(f'result/{date}/{domain}.links.csv') as f:
            reader = csv.reader(f)
            next(reader)
            for row in reader:
                # print(type(row[2]))  dict(json.loads(row[2]))
                # print({"method":row[0],"url":row[1],"headers":dict(json.loads(row[2])),"data":row[3]})
                request0({"method": row[0], "url": row[1], "headers": row[2], "data": row[3]})

    # 目前只支持urls文件，单个url也是写入文件，然后工具从文件中读取
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
        # if get_system() =="":
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)
        ports_str = "21,22,23,25,53,53,69,80,81,88,110,111,111,123,123,135,137,139,161,177,389,427,443,445,465,500,515," \
                    "520,523,548,623,626,636,873,902,1080,1099,1433,1434,1521,1604,1645,1701,1883,1900,2049,2181,2375," \
                    "2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379," \
                    "7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,11211,27017,33848," \
                    "37777,50000,50070,61616"
        ports_str = "21,22,80,81,445,1433,1521,3306,6379,3389,7001,8009,8080,8081,8443"

        # -host 121.46.128.13 -p 80-443 -scan-all-ips -no-color -o 2.txt -rate 100
        # 目前只支持urls文件，单个url也是写入文件，然后工具从文件中读取
        if urlsfile:
            cmdstr = f'{pwd}/vscan/vscan{suffix} -l {urlsfile} -rate 150 -scan-all-ips -no-color -csv -o {vulscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.csv'
        else:
            logger.error("Please check urlsfile")
            return
        logger.info(f"[+] command:{cmdstr}")
        # __subprocess1(cmdstr, timeout=None)
        os.system(cmdstr)

    def run():
        if progress_record(date=date, module="vulscan", submodule="webattack", finished=False) is False:
            # {domain}.subdomain_with_http.txt
            nuclei(urlsfile=urlsfile)
            afrog(urlsfile=urlsfile)
            vulmap(urlsfile=urlsfile)
            # to_xray()
            # 扫描敏感目录和弱口令爆破
            vscan(urlsfile=urlsfile)
            progress_record(date=date, module="vulscan", submodule="webattack", finished=True)
            logger.info('-' * 10 + f'finished {sys._getframe().f_code.co_name}' + '-' * 10)

    run()


# 对ip进行扫描
@logger.catch
def hostmanager(domain=None, ip=None, ipfile=None, date="2022-09-02-00-01-39"):
    logger.info('\n' + '<' * 18 + f'start {__file__}' + '>' * 18)
    suffix = get_system()
    root = os.getcwd()
    pwd_and_file = os.path.abspath(__file__)
    pwd = os.path.dirname(pwd_and_file)  # E:\ccode\python\006_lunzi\core\tools\domain
    # 获取当前目录的前三级目录，即到domain目录下，来寻找exe domain目录下
    grader_father = os.path.abspath(os.path.dirname(pwd_and_file) + os.path.sep + "../..")
    # 创建存储子域名工具扫描结果的文件夹
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

    # ip参数支持c段，直接使用其他工具测也可以
    @logger.catch
    def goon(ip=ip, ipfile=ipfile):
        '''
        goon v3.5 使用goon 进行端口扫描，端口指纹识别，和简单的端口服务爆破
        输出目录
        :return:
        '''
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)
        if ip:
            cmdstr = f'{os.path.realpath(f"{pwd}/goon/goon{suffix}")} -ip {ip} -ofile {vulscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.txt'
        elif ipfile:
            cmdstr = f'{os.path.realpath(f"{pwd}/goon/goon{suffix}")} -ifile {ipfile} -ofile {vulscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.txt'
        else:
            logger.error("Please check ip or ipfile")
            return
        logger.info(f"[+] command:{cmdstr}")
        # __subprocess1(cmdstr, timeout=None)
        os.system(cmdstr)

    # 只是为了统一 -host参数可以为单ip cidr 也可以为文件
    @logger.catch
    def SweetBabyScan(ip=ip, ipfile=ipfile):
        '''
        SweetBabyScan v0.1.0
        目前输出文件-oe -ot 参数不可用，指定不生效，对原文件进行了修改默认进行截屏，改成了false 在编译的。
        ++SweetBabyScan-轻量级内网资产探测漏洞扫描工具类似fscan，集成了xray和nucleipoc--inbug-team
            主机[IP&域名]存活检测，支持PING/ICMP模式
            端口[IP&域名]服务扫描
            网站爬虫截图，CMS识别
            Nuclei & Xray POC
            网卡识别、域控识别、SMBGhost、MS17017
            弱口令爆破：
            文件：FTP/SMB
            远程：SSH/RDP/SNMP
            数据库：Redis/MongoDB/MySQL/SQLServer/PgSQL/ES/Oracle/Memcached
        SbScanAmd64_false.exe -host 44.228.249.3 -p normal -wsh 150 -wsp 150 -is False -oe 1/xx.xlsx -ot 1/xx.txt
        输出目录
        :return:
        '''
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)
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
        # __subprocess1(cmdstr, timeout=None)
        os.system(cmdstr)

    # ip参数支持c段，直接使用其他工具测也可以
    @logger.catch
    def vscan(ip=ip, ipfile=ipfile):
        '''
        vscan v2.1
        zhuyi:由于权限要求，不能使用子线程执行，只能使用主线程执行即os.system执行
        改自nabbu，进行端口扫描，端口指纹识别，和简单的端口服务爆破
        说白了也是一个web扫描，移植的naabu,在naabu的基础上添加了一些功能，当使用-top-ports的时候
        直接调用原生naabu只扫描端口不识别指纹，不进行其他附加工作，即使有web，但使用-p参数可以，
        输入可以是url可以是ip，如果是url则只进行web探测，bug点
        输出目录
        :return:
        '''
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)
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
        # __subprocess1(cmdstr, timeout=None)
        os.system(cmdstr)

    def run():
        if progress_record(date=date, module="vulscan", submodule="hostattack", finished=False) is False:
            goon(ip=ip, ipfile=ipfile)
            # 暂未使用，主要是会下载chromewin每次执行
            SweetBabyScan(ip=ip, ipfile=ipfile)
            vscan(ip=ip, ipfile=ipfile)
            progress_record(date=date, module="vulscan", submodule="hostattack", finished=True)
            logger.info('-' * 10 + f'finished {sys._getframe().f_code.co_name}' + '-' * 10)

    run()


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
    # manager(domain="tiqianle.com", date="2022-09-02-00-01-39")
    # webmanager(domain="vulweb.com",url=None,urlsfile=None, date="2022-09-02-00-01-39")
    # hostmanager(domain='vulweb.com', ip=None, ipfile=None, date="2022-09-02-00-01-39")
    # hostmanager(domain=None, ip=None, ipfile='result/2022-09-02-00-01-39/vulnweb.com.subdomains.ips.txt', date="2022-09-02-00-01-39")
