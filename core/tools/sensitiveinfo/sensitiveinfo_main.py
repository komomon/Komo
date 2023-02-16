import base64
import csv
import hashlib
import inspect
import json
import os
import re
import subprocess
import requests
import platform
import shlex
import yaml
from fake_useragent import UserAgent
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import sys
from urllib.parse import urlsplit
import tempfile
import time
import traceback
import shutil
import dns
import fire
import simplejson
import tldextract
from loguru import logger
from common.getconfig import *

# import common

all_config = getconfig()
Xray_Port = int(all_config['tools']['other']['xray']['listenport'])


def create_logfile():
    if os.path.exists(f'{os.getcwd()}/log') is False:
        os.makedirs(f'{os.getcwd()}/log')
    logger.add(sink='log/runtime.log', level='INFO', encoding='utf-8')
    logger.add(sink='log/error.log', level='ERROR', encoding='utf-8')


# 暂未使用
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


# 暂不使用
def getconfig_():
    # ostype = platform.system().lower() #get_system()
    toolsyaml_path = f"{os.path.realpath(f'{os.path.dirname(os.path.abspath(__file__))}/../../../')}/config/config.yaml"
    # toolsyaml_path = "tools_linux.yaml"
    if os.path.exists(toolsyaml_path):
        with open(toolsyaml_path, 'r', encoding='utf-8') as f:
            tools_config = yaml.load(f, Loader=yaml.FullLoader)['tools']
        return tools_config
    else:
        logger.error(f"[-] not found {toolsyaml_path}")
        logger.error("Exit!")
        exit(1)


# 进度记录,基于json
def progress_record_old(date=None, target=None, module=None, submodule=None, value=None, finished=False):
    logfile = f"result/{date}/log.json"
    if os.path.exists(logfile) is False:
        shutil.copy("config/log_template.json", f"result/{date}/log.json")
    with open(logfile, 'r', encoding='utf-8') as f1:
        log_json = json.loads(f1.read())
    # if module in dict(log_json).keys() and target:
    # 先检查是否存在于scanned_targets 不存在则开始扫
    if finished is False:
        if target not in log_json[module]["scanned_targets"]:
            return False
        else:
            return True
        # finished flag设置则证明扫描完成
    elif finished is True:
        log_json[module]["scanned_targets"].append(target)
        with open(logfile, "w", encoding="utf-8") as f:
            f.write(json.dumps(log_json))
        return True


# 进度记录,基于json
def progress_record(date=None, target=None, subtarget=None, module="sensitiveinfo", value=None, finished=False):
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
        # return False
    with open(logfile, "r", encoding="utf-8") as f1:
        log_json = json.loads(f1.read())
    if finished is False:
        # 读取log.json 先判断target_logdict是否存在，不存在则加进去
        if target not in dict(log_json["target_log"]).keys():
            log_json["target_log"][target] = target_log
            with open(logfile, "w", encoding="utf-8") as f:
                f.write(json.dumps(log_json))
            return False  # 即未扫描 true为扫描了
        else:
            # 检测是否扫瞄过
            if subtarget in log_json["target_log"][target][module]["scanned_targets"]:
                return True
            else:
                return False
    elif finished is True:
        # 如果已经存在对应目标的target_log 字典,则直接修改即可，否则添加target_log 并将domain键值设为true
        log_json["target_log"][target][module]["scanned_targets"].append(subtarget)
        with open(logfile, "w", encoding="utf-8") as f:
            f.write(json.dumps(log_json))
        return True


# 进度记录,基于json,暂时弃用，记录log比较详细的版本，需要考虑记住本次扫描的是哪个url，下次先读取url
def progress_record_(date=None, target=None, module=None, submodule=None, value=None, submodule_finished=False,
                     target_finished=False, ):
    logfile = f"result/{date}/log.json"
    if os.path.exists(logfile) is False:
        shutil.copy("config/log_template.json", f"result/{date}/log.json")
    with open(logfile, "r", encoding="utf-8") as f1:
        log_json = json.loads(f1.read())
    if target_finished is False:
        if target not in log_json[module]["scanned_targets"]:
            return False
        else:
            return True
        # if submodule_finished is False:
        #     # 读取log.json 如果是false则扫描，是true则跳过
        #     if log_json[module][submodule] is False:
        #         return False
        #     elif log_json[module][submodule] is True:  # 即log_json[module] 为true的情况
        #         return True
        # elif submodule_finished is True:
        #     log_json[module][submodule] = True
        #     with open(logfile, "w", encoding="utf-8") as f:
        #         f.write(json.dumps(log_json))
        #     return True
    elif target_finished is True:
        log_json[module]["scanned_targets"].append(target)
        with open(logfile, "w", encoding="utf-8") as f:
            f.write(json.dumps(log_json))
        return True


def makedir0(path):
    if os.path.exists(path) is False:
        os.makedirs(path)
        logger.info(f'[+] Create {path} success.')


# 每个函数的结果都存到 result/{date}/domain_log下
# 装饰器
def additional(func1):
    def init2():
        logger.info(f'[+] start {func1.__qualname__}')
        func1()
        logger.info(f'[+] finish {func1.__qualname__}')

    return init2


def to_file(filename, data: list, mmode='a'):
    # 将links记录到 result/{date}/{domain}.links.csv中
    with open(filename, mmode, encoding="utf-8") as f1:
        for i in data:
            f1.write(i + "\n")


def to_csv(filename, data: list, mmode='a'):
    # with open(f"{root}/result/{date}/{domain}.links.csv", "a", encoding="utf-8") as f1:
    with open(filename, mmode, encoding="utf-8", newline='') as f1:
        writer = csv.writer(f1)
        for row in data:
            writer.writerow(row)


# @logger.catch
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
            logger.info(f"Port {port} is open")
            return True
        else:
            logger.error(f'Port {port} is not open')
            return False


def kill_process(processname):
    if 'win32' == sys.platform:
        cmd = f'''for /f "tokens=2 " %a in ('tasklist  /fi "imagename eq {processname}" /nh') do taskkill /f /pid %a'''
        process = os.popen(cmd).read()
        logger.info(f"[+] kill {processname}, {process}")
        # print(process)
        # if process:
        #     os.popen('nohup kill -9 {} 2>&1 &'.format(process.replace('\n', ' ')))
    elif 'linux' == sys.platform:
        cmd = f"ps aux | grep '{processname}'|grep -v 'color' | awk '{{print $2}}'"
        process = os.popen(cmd).read()
        print(process)
        if process:
            os.popen('nohup kill -9 {} 2>&1 &'.format(process.replace('\n', ' ')))
            logger.info(f"[+] kill {processname}, {process}")
    else:
        logger.error('Unsupported system type %s' % sys.platform)
        return False

    # os.system(cmd)


# 打印脚本跑出了几个新的子域名，并返回最新最全的子域名列表  传递两个列表，old是前面收集好的子域名，new是刚跑完的脚本收集的子域名，进行比较.
# def printGetNewSubdomains(old_subdomains, new_subdomains):
#     if len(old_subdomains) > 0:
#         newSubdomains = list(set(new_subdomains) - set(old_subdomains))
#         print('[new :{}] {}'.format(len(newSubdomains), newSubdomains))
#     return list(set(new_subdomains + old_subdomains))

# @logger.catch
def request0(req_json):
    proxy_port = Xray_Port
    proxies = {
        'http': f'http://127.0.0.1:{proxy_port}',
        'https': f'http://127.0.0.1:{proxy_port}'
    }
    ua = UserAgent()
    headers = {'User-Agent': ua.random}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"}
    method0 = req_json['method']
    urls0 = req_json['url']
    headers0 = json.loads(req_json['headers']) if str(
        req_json['headers']).strip() != "" else headers if "headers" in req_json.keys() else ""
    data0 = req_json['data'] if "data" in req_json.keys() else ""
    try:
        if (method0 == 'GET'):
            a = requests.get(urls0, headers=headers0, proxies=proxies, timeout=15, verify=False)
            # opt2File(urls0)
        elif (method0 == 'POST'):
            a = requests.post(urls0, headers=headers0, data=data0, proxies=proxies, timeout=15, verify=False)
            # opt2File(urls0)
    except:
        pass


# 启用子进程执行外部shell命令,目前未使用
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
        rt_list = rt.strip().split(b"\n")
    except Exception as e:
        logger.error(traceback.format_exc())
        # print(traceback.format_exc())
    finally:
        if out_temp:
            out_temp.close()
    return rt_list


# 启用子进程执行外部shell命令
# @logger.catch
def __subprocess1(cmd, timeout=None, path=None):
    '''
    rad 不支持结果输出到管道所以stdout=None才可以，即默认不设置
    :param cmd:
    :param timeout:
    :param path:
    :return:
    '''
    f_name = inspect.getframeinfo(inspect.currentframe().f_back)[2]
    # cmd = shlex.split(cmd)
    logger.info(f"[+] command:{cmd}")
    p = subprocess.Popen(cmd, shell=True, cwd=path)
    # p = subprocess.Popen(cmd, shell=True,cwd=path,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        # outs, errs = p.communicate(timeout=timeout)
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired as e:
        # logger.error('{} - {} - \n{}'.format(self.domain, self.__class__.__name__, e))
        logger.error(traceback.format_exc())
        # outs, errs = p.communicate()
        p.kill()
        kill_process(f_name + get_system())
    except Exception as e:
        logger.error(traceback.format_exc())
        # logger.error(f'{sys._getframe().f_code.co_name} Reach Set Time and exit')
    finally:
        logger.info(f'{f_name} finished.')
        kill_process(f_name + get_system())


# @logger.catch
def __subprocess2(cmd):
    lines = []
    out_temp = tempfile.SpooledTemporaryFile(max_size=10 * 1000, mode='w+b')
    try:
        # cmd = "ls -lh"
        # logger.info(f"[+] command:{' '.join(cmd)}")
        fileno = out_temp.fileno()
        obj = subprocess.Popen(cmd, stdout=fileno, stderr=fileno, shell=True)
        obj.wait()
        out_temp.seek(0)
        lines = out_temp.readlines()
        # print(lines)
    except Exception as e:
        logger.error(traceback.format_exc())
    finally:
        if out_temp:
            out_temp.close()
    return lines


# 废弃 将请求发给xray
@logger.catch
def to_xray(urls, attackflag=None, fromurl=None):
    # headers = {
    #     'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36 Edg/98.0.1108.43'}
    xrayport = Xray_Port
    black_list = ['.jpg', '.gif', '.png', '.css', '.pdf', '.doc', '.docx', '.xlsx', '.csv', '.svg']
    # domain_suffix = tldextract.extract(fromurl)  # 通过域名后缀是否为空判断给的domain是domain 还是randomstr
    # ExtractResult(subdomain='', domain='sdadadadawdawd', suffix='')
    # ExtractResult(subdomain='ss', domain='sss', suffix='com')
    if attackflag:
        if checkport(xrayport):
            for url in urls:
                # SplitResult(scheme='https', netloc='ss.sss.com', path='/dad/da/ddsad', query='a=a&b=123', fragment='')
                splitresult = urlsplit(url)
                ssubdomain = splitresult.netloc
                uri = splitresult.path
                # 只发送给xray要爬取的网站的url
                if urlsplit(fromurl).netloc == ssubdomain:
                    if os.path.splitext(uri)[1] not in black_list:
                        request0({"method": "GET", "url": url, "headers": "", "data": ""})
                # links_set.add(url)
        else:
            logger.error(f"xray not running on {xrayport}! skip to xray attack!")


@logger.catch
def manager(domain=None, url=None, urlsfile=None, attackflag=False, date="2022-09-02-00-01-39"):
    '''
    获取敏感信息
    crawlergo rad,URLFinder 爬取url，attackflag标志位设定是否传给xray进行攻击
    两种模式
        1 每个模块顺序调用到sensitiveinfo_main模块，只需传入domain即可
        2 单独使用该模块，只需传入urlsfile或url即可
    :param domain:
    :param urlsfile:
    :param attackflag: 标志位设定是否传给xray进行攻击，如果为true，记得开启xray监听127.0.0.1:7777
    :param date:
    :return:
    '''
    logger.info('\n' + '<' * 18 + f'start {__file__}' + '>' * 18)
    global Xray_Port
    if attackflag:
        # 端口没开则直接结束
        if checkport(Xray_Port) is False:
            logger.error(f"xray_port {Xray_Port} not open, Exit!")
            exit(1)
    # isdomain = False
    # 两种模式,三种情况
    if domain and urlsfile is None and url is None:
        # isdomain = True
        urlsfile = f"result/{date}/{domain}.subdomains.with.http.txt"
        # output_filename_prefix = domain
    elif urlsfile and domain is None and url is None:
        domain = date
        urlsfile = urlsfile
        # output_filename_prefix = date
    elif url and domain is None and urlsfile is None:
        domain = '.'.join(part for part in tldextract.extract(url) if part)
        urlsfile = f"temp.sensitiveinfo_main.txt"
        # output_filename_prefix = '.'.join(part for part in tldextract.extract(url) if part)
        with open(urlsfile, "w", encoding="utf-8") as f:
            f.write(url)
    else:
        logger.error(f"[-] domain:{domain},urlsfile:{urlsfile},url:{url} 只能一个不为None")
        exit()
    ostype = platform.system().lower()
    suffix = ".exe" if "windows" == ostype else ""
    root = os.getcwd()
    pwd_and_file = os.path.abspath(__file__)
    pwd = os.path.dirname(pwd_and_file)  # E:\ccode\python\006_lunzi\core\tools\sensitiveinfo
    # 获取当前目录的前三级目录，即到domain目录下，来寻找exe domain目录下
    grader_father = os.path.abspath(os.path.dirname(pwd_and_file) + os.path.sep + "../..")
    # print(grader_father) # E:\ccode\python\006_lunzi\core
    # 存储爬取到的links，不在其中的 links.csv 存储该结果
    links_set = set()

    # 创建存储工具扫描结果的文件夹
    sensitiveinfo_log_folder = f"{root}/result/{date}/sensitiveinfo_log"
    makedir0(sensitiveinfo_log_folder)

    # 初始话往result/{date}/{domain}.links.csv  写入 title
    to_csv(f"result/{date}/{domain}.links.csv", [["tool", "method", "url", "header", "body"]], mmode='a')

    # 爬取url的link  result/{date}/sensitiveinfo_log/{domain}.{tool_name}.json
    @logger.catch
    def crawlergo(data1, attackflag=attackflag):
        '''
        只能单个url,爬取网站的url,保存完整请求到json文件，并存储一份"method url"的txt
        crawlergo 0.4.3
        存储的在：{sensitiveinfo_log_folder}/{subdomain}.{tool_name}.json
        :return:
        '''
        tool_name = str(sys._getframe().f_code.co_name)
        logger.info('<' * 10 + f'start {tool_name}' + '>' * 10)
        # 创建多个子域名结果输出文件夹
        output_folder = f'{sensitiveinfo_log_folder}/{tool_name}_log'
        makedir0(output_folder)

        target = data1
        # ExtractResult(subdomain='www', domain='worldbank', suffix='org.kg')
        subdomain_tuple = tldextract.extract(data1)
        output_filename_prefix = '.'.join(part for part in subdomain_tuple if part)
        # cmd = [".\crawlergo.exe", "-c", ".\chrome-win\chrome.exe", "-t","20", "-f", "smart", "--fuzz-path", "--output-mode", "json", target]
        # --fuzz-path  --robots-path --max-tab-count Number, -t Number 默认8
        #  --push-to-proxy待接收爬虫结果的监听地址，通常是被动扫描器的监听地址。（默认值：空）
        # --push-pool-max将爬虫结果发送到监听地址时的最大并发数。（默认：10）
        # --max-tab-count Number, -t Number
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"
        }
        # cmd = ["./crawlergo", "-c", "/usr/bin/google-chrome","-t", "10","-f","smart","--fuzz-path", "--output-mode", "json","--ignore-url-keywords", "quit,exit,logout",  "--custom-headers", simplejson.dumps(headers),"--robots-path","--log-level","debug","--push-to-proxy","http://xray_username:xray_password@xray_ip:xray_port",target]
        # cmdstr = f"crawlergo_windows_amd64_0.4.3.exe -c chrome-win/chrome.exe -t 8 -f smart --fuzz-path --robots-path --custom-headers {simplejson.dumps(headers)} --output-mode json --output-json crawlergo.json --push-to-proxy http://xray_username:xray_password@xray_ip:xray_port {target}"
        xray_port = Xray_Port
        if attackflag:
            proxy = f"http://127.0.0.1:{xray_port}"
            # --custom-headers {simplejson.dumps(headers)} --custom-headers "{\"Cookie\": \"security=low; PHPSESSID=n1vcllnmecmr9ga4v5ggmq76a2\"}"
            # --max-tab-count  (Default: 8)
            cmdstr = f"{pwd}/crawlergo/crawlergo{suffix} -c {pwd}/chrome-{ostype}/chrome{suffix}  -t 8 -f smart  --fuzz-path --robots-path --output-mode json --output-json {output_folder}/{output_filename_prefix}.{tool_name}.json --push-to-proxy {proxy} {target}"
        else:
            cmdstr = f"{pwd}/crawlergo/crawlergo{suffix} -c {pwd}/chrome-{ostype}/chrome{suffix} -t 8 -f smart  --fuzz-path --robots-path --output-mode json --output-json {output_folder}/{output_filename_prefix}.{tool_name}.json {target}"

        logger.info(f"[+] command:{cmdstr}")
        runtime = all_config['tools']['sensitiveinfo'][tool_name]['runtime']
        # 如果runtime为空则不限时，如果为0 则跳过该工具执行，如果为指定数字则限时执行
        if runtime is None:
            __subprocess1(cmdstr, timeout=None, path=f"{pwd}/{tool_name}")
        else:
            runtime = int(runtime)
            if runtime != 0:
                __subprocess1(cmdstr, timeout=runtime, path=f"{pwd}/{tool_name}")
            else:
                # 跳过该工具执行
                return False
        # 结果处理：存储到links.csv
        # 从crawlergo结果中获取url 存储crawlergo爬取到的url method headers body, result/{date}/{domain}.links.csv,也进行了去重处理
        urls_data_tmp_to_csv = []  # 存储urldata四个字段的列表
        # 从结果中获取url,不存在url的则写入csv和links_set
        if os.path.exists(f"{output_folder}/{output_filename_prefix}.{tool_name}.json"):
            with open(f"{output_folder}/{output_filename_prefix}.{tool_name}.json", "r",
                      encoding="utf-8", errors='ignore') as f2:
                result = json.loads(f2.read())
                req_list = result["all_req_list"]  # req_list
                sub_domain_list = result["sub_domain_list"]
                # 新方法，和下面的工具统一，新增结果存储到urls_data_tmp_to_csv，然后再存入csv
                for req in req_list:
                    if req['url'] not in links_set:
                        # del req["headers"]["Spider-Name"]
                        urls_data_tmp_to_csv.append(
                            [tool_name, req['method'], req['url'], json.dumps(req['headers']), req['data']])
                        links_set.add(req['url'])
                    elif req['method'] != "GET":
                        # del req["headers"]["Spider-Name"]
                        urls_data_tmp_to_csv.append(
                            [tool_name, req['method'], req['url'], json.dumps(req['headers']), req['data']])
                to_csv(f"result/{date}/{domain}.links.csv", urls_data_tmp_to_csv, mmode='a')
                logger.info(f'[+] From url {target} found {len(req_list)} links')
                logger.info(f'[+] Links file exist:{root}/result/{date}/{domain}.links.csv')
                # 存储crawlergo爬取到的子域名
                if sub_domain_list is not None:
                    with open(f"{sensitiveinfo_log_folder}/{domain}.subdomains.{tool_name}.txt", "a",
                              encoding="utf-8") as f2:
                        for i in sub_domain_list:
                            f2.write(i + "\n")
        else:
            logger.error(f'{tool_name} not found {output_folder}/{output_filename_prefix}.{tool_name}.json')
        logger.info(f"[+] {tool_name} finished: {target}")

    # 爬取url的link  result/{date}/sensitiveinfo_log/{domain}.{tool_name}.json
    @logger.catch
    def rad(data1, attackflag=attackflag):
        '''
        只能单个url,爬取网站的url,保存完整请求到json文件，并存储一份"method url"的txt
        rad 0.4
        :return:
        '''
        global Xray_Port
        tool_name = str(sys._getframe().f_code.co_name)
        logger.info('<' * 10 + f'start {tool_name}' + '>' * 10)
        # 创建多个子域名结果输出文件夹
        output_folder = f'{sensitiveinfo_log_folder}/{tool_name}_log'
        makedir0(output_folder)
        xray_port = Xray_Port
        target = data1
        subdomain_tuple = tldextract.extract(data1)
        output_filename_prefix = '.'.join(part for part in subdomain_tuple if part)
        # cmd = ["rad.exe", "--http-proxy", "http://127.0.0.1:7777", "--target", target]
        # 提前删除结果文件，否则rad报错，结果文件已存在
        print(f"{output_folder}/{output_filename_prefix}.{tool_name}.json")
        if os.path.exists(f"{output_folder}/{output_filename_prefix}.{tool_name}.json"):
            os.remove(f"{output_folder}/{output_filename_prefix}.{tool_name}.json")
            logger.info(f"{output_folder}/{output_filename_prefix}.{tool_name}.json delete success!")
        time.sleep(2)

        if attackflag:
            # 端口没开则直接结束
            # if checkport(xray_port) is False:
            #     logger.error(f"xray_port {xray_port} not open, {tool_name} skip")
            #     return False
            proxy = f"http://127.0.0.1:{xray_port}"
            cmdstr = f"{pwd}/rad/rad{suffix} --target {target} --json-output {output_folder}/{output_filename_prefix}.{tool_name}.json --http-proxy {proxy}"
        else:
            cmdstr = f"{pwd}/rad/rad{suffix} --target {target} --json-output {output_folder}/{output_filename_prefix}.{tool_name}.json"
        logger.info(f"[+] command:{cmdstr}")
        # __subprocess1(cmdstr, timeout=int(all_config['tools']['sensitiveinfo'][tool_name]['runtime']),
        #               path=f"{pwd}/{tool_name}")
        runtime = all_config['tools']['sensitiveinfo'][tool_name]['runtime']
        # 如果runtime为空则不限时，如果为0 则跳过该工具执行，如果为指定数字则限时执行
        if runtime is None:
            __subprocess1(cmdstr, timeout=None, path=f"{pwd}/{tool_name}")
        else:
            runtime = int(runtime)
            if runtime != 0:
                __subprocess1(cmdstr, timeout=runtime, path=f"{pwd}/{tool_name}")
            else:
                # 跳过该工具执行
                return False
        # __subprocess1(cmdstr, timeout=int(all_config['tools']['sensitiveinfo'][tool_name]['runtime']),
        #               path=f"{pwd}/{tool_name}")

        urls_data_tmp_to_csv = []  # 存储urldata四个字段的列表
        # 从rad结果中获取url,不存在url的则写入csv和links_set
        if os.path.exists(f"{output_folder}/{output_filename_prefix}.{tool_name}.json"):
            with open(f"{output_folder}/{output_filename_prefix}.{tool_name}.json", "r",
                      encoding="utf-8", errors='ignore') as f2:
                # result = json.loads(f2.read())
                for i in f2.readlines()[1:-1]:
                    # row = simplejson.loads(simplejson.dumps(i.rstrip().rstrip(',')))
                    row = simplejson.loads(i.rstrip().rstrip(','))
                    if row['Method'] == "POST":
                        if 'b64_body' in row.keys():
                            data = [tool_name, row["Method"], row["URL"], json.dumps(row["Header"]),
                                    base64.b64decode(row["b64_body"]).decode()]
                        else:
                            data = [tool_name, row["Method"], row["URL"], json.dumps(row["Header"]), ""]
                        # data = row["Method"] + "," + row["URL"] + "," + str(row["Header"]) + "," + base64.b64decode(row["b64_body"])
                        urls_data_tmp_to_csv.append(data)
                        links_set.add(row["URL"])
                    else:
                        if row["URL"] not in links_set:
                            data = [tool_name, row["Method"], row["URL"], json.dumps(row["Header"]), ""]
                            urls_data_tmp_to_csv.append(data)
                            links_set.add(row["URL"])
                    # 老版按存在不存在区分，POST的全存储
                    # if row["URL"] not in links_set:
                    #     if row["Method"] == "GET":
                    #         data = [tool_name, row["Method"], row["URL"], json.dumps(row["Header"]), ""]
                    #     elif row["Method"] == "POST":
                    #         # print(base64.b64decode(row["b64_body"]))
                    #         if 'b64_body' in row.keys():
                    #             data = [tool_name, row["Method"], row["URL"], json.dumps(row["Header"]),
                    #                     base64.b64decode(row["b64_body"]).decode()]
                    #         else:
                    #             data = [tool_name, row["Method"], row["URL"], json.dumps(row["Header"]), ""]
                    #         # data = row["Method"] + "," + row["URL"] + "," + str(row["Header"]) + "," + base64.b64decode(row["b64_body"])
                    #     urls_data_tmp_to_csv.append(data)
                    #     links_set.add(row["URL"])
                    # elif row['Method'] == "POST":
                    #     if 'b64_body' in row.keys():
                    #         data = [tool_name, row["Method"], row["URL"], json.dumps(row["Header"]),
                    #                 base64.b64decode(row["b64_body"]).decode()]
                    #     else:
                    #         data = [tool_name, row["Method"], row["URL"], json.dumps(row["Header"]), ""]
                    #     # data = row["Method"] + "," + row["URL"] + "," + str(row["Header"]) + "," + base64.b64decode(row["b64_body"])
                    #     urls_data_tmp_to_csv.append(data)
                    #     links_set.add(row["URL"])
            # 存储rad 爬取到的url method headers body
            to_csv(f"result/{date}/{domain}.links.csv", urls_data_tmp_to_csv, mmode='a')
        else:
            logger.error(f'{tool_name} not found {output_folder}/{output_filename_prefix}.{tool_name}.json')
        logger.info(f"[+] {tool_name} finished: {target}")

    # URLFinder爬取
    @logger.catch
    def URLFinder(data1, attackflag=attackflag):
        '''
        URLFinder v
        urlfinder 的输出结果是domain:port.csv ip:port.csv 如果有port的话
        可以单个url,爬取网站的url,保存完整请求到json文件，并存储一份"method url"的txt
        可以多个url，一个url一个csv 格式子域名.csv
        结果文件 ：{output_filename}/{output_filename}.json 域名如果有冒号会自动变成中文冒号
        这个工具可能存在内存越界报错的情况 20230202
        :return: jieguowenjian:new.xxx.com.cn：443.csv 中文冒号
        '''
        tool_name = str(sys._getframe().f_code.co_name)
        logger.info('<' * 10 + f'start {tool_name}' + '>' * 10)

        # 创建多个子域名结果输出文件夹
        output_folder = f'{sensitiveinfo_log_folder}/{tool_name}_log'
        makedir0(output_folder)

        target = data1
        urls_data_tmp_to_csv = []
        urls_set_tmp = set()

        # 结果文件名 {subdomain}.csv {sensitiveinfo_log_folder}/URLFinder_log/{domain}.{tool_name}.csv
        cmdstr = f'{pwd}/URLFinder/URLFinder{suffix} -u {target} -s all -t 50 -m 2 -o {output_folder}'
        logger.info(f"[+] command:{cmdstr}")
        # __subprocess1(cmdstr, timeout=int(all_config['tools']['sensitiveinfo'][tool_name]['runtime']),
        #               path=f"{pwd}/{tool_name}")
        runtime = all_config['tools']['sensitiveinfo'][tool_name]['runtime']
        # 如果runtime为空则不限时，如果为0 则跳过该工具执行，如果为指定数字则限时执行
        if runtime is None:
            __subprocess1(cmdstr, timeout=None, path=f"{pwd}/{tool_name}")
        else:
            runtime = int(runtime)
            if runtime != 0:
                __subprocess1(cmdstr, timeout=runtime, path=f"{pwd}/{tool_name}")
            else:
                # 跳过该工具执行
                return False
        # logger.info(f"[+] {tool_name} finished: {target}")

        # 对结果处理，不在links_set的就存储到link.csv中
        groups_tmp = urlsplit(target)
        output_filename = groups_tmp[1].replace(':', '：')
        # 新版通过json处理
        if os.path.exists(f'{output_folder}/{output_filename}/{output_filename}.json'):
            with open(f'{output_folder}/{output_filename}/{output_filename}.json', 'r', encoding="utf-8",
                      errors='ignore') as f:
                result = json.loads(f.read())
                # {"fuzz": [],"info": {}, "js": null,"jsOther": [],"url": [], "urlOther": []}
                # "url": [{
                #     "Url": "http://testphp.vulnweb.com:80/Templates/main_dynamic_template.dwt.php",
                #     "Status": "200",
                #     "Size": "4697",
                #     "Title": "Document titleg",
                #     "Source": "http://testphp.vulnweb.com:80"
                # }...
                for i in result["url"]:
                    if i["Status"] != "404" and i["Url"] not in links_set:
                        # data = f'GET,{row[0]},,'
                        data = [tool_name, "GET", i["Url"], "", ""]
                        # data = [tool_name, "GET", i["Url"], i["Title"], "", ""]
                        urls_data_tmp_to_csv.append(data)
                        urls_set_tmp.add(i["Url"])
                        links_set.add(i["Url"])  # links_set 增加新的
            # 差集发送给xray,攻击模式端口没,则只收集跳过发送给xray的攻击扫描
            to_xray(urls_set_tmp, attackflag=attackflag, fromurl=target)

            # 存储rad 爬取到的url method headers body
            # with open(f"{root}/result/{date}/{domain}.links.csv", "a", encoding="utf-8") as f1:
            to_csv(f"result/{date}/{domain}.links.csv", urls_data_tmp_to_csv, mmode='a')
        else:
            logger.error(f'{tool_name} not found {output_folder}/{output_filename}/{output_filename}.json')
        logger.info(f"[+] {tool_name} finished: {target}")
        # 老版通过csv处理的工具
        # if os.path.exists(f'{output_folder}/{output_filename}/{output_filename}.csv'):
        #     with open(f'{output_folder}/{output_filename}/{output_filename}.csv', 'r', encoding="utf-8", errors='ignore') as f:
        #         reader = csv.reader(f)
        #         for row in reader:
        #             if len(row) != 0:
        #                 if f"URL to {groups_tmp[1].split(':')[0]}" in row[0]:
        #                     # num = reader.line_num
        #                     break
        #         for row in reader:
        #             if len(row) != 0:
        #                 if row[1] == "200" and row[0] not in links_set:
        #                     # data = f'GET,{row[0]},,'
        #                     data = [tool_name, "GET", row[0], "", ""]
        #                     urls_data_tmp_to_csv.append(data)
        #                     urls_set_tmp.add(row[0])
        #                     links_set.add(row[0])  # links_set 增加新的
        #             else:
        #                 break  # 在读到空行则说明结果中的子域部分解释，终止
        # else:
        #     logger.error(f'URLFinder not found {output_folder}/{output_filename}/{output_filename}.csv')

    @logger.catch
    def gospider(data1, attackflag=attackflag):
        '''
        gospider 1.7.1
        gospider.exe -S 1.txt --depth 0 --js --subs --sitemap --robots --other-source --include-subs --include-other-source  --quiet --output 1
        gospider的输出是 xx_xx_xx ip xx_xx_xx_xx 都不带端口 无后缀
        :param data1: gospider 要求url必须以http/https开头
        :param attackflag:
        :return:
        '''
        tool_name = str(sys._getframe().f_code.co_name)
        logger.info('<' * 10 + f'start {tool_name}' + '>' * 10)
        # 创建多个子域名结果输出文件夹
        output_folder = f'{sensitiveinfo_log_folder}/{tool_name}_log'
        makedir0(output_folder)

        target = data1
        if 'http://' not in target and 'https://' not in target:
            logger.error(f"{tool_name} can't run: {target} Exclude http or https")
            return
        subdomain_tuple = tldextract.extract(target)
        output_filename = '.'.join(part for part in subdomain_tuple if part).replace('.',
                                                                                     '_')  # www_baidu_com 127_0_0_1
        urls_data_tmp_to_csv = []
        urls_set_tmp = set()
        # 结果文件名 xx_xx_xx 结果是指定文件夹 --include-other-source Also include other-source's urls (still crawl and request)
        cmdstr = f'{pwd}/gospider/gospider{suffix} -s {target} --threads 10 --depth 2 --js --subs --sitemap --robots --other-source --include-subs --quiet --output {output_folder}'
        logger.info(f"[+] command:{cmdstr}")
        # __subprocess1(cmdstr, timeout=int(all_config['tools']['sensitiveinfo'][tool_name]['runtime']),
        #               path=f"{pwd}/{tool_name}")
        runtime = all_config['tools']['sensitiveinfo'][tool_name]['runtime']
        # 如果runtime为空则不限时，如果为0 则跳过该工具执行，如果为指定数字则限时执行
        if runtime is None:
            __subprocess1(cmdstr, timeout=None, path=f"{pwd}/{tool_name}")
        else:
            runtime = int(runtime)
            if runtime != 0:
                __subprocess1(cmdstr, timeout=runtime, path=f"{pwd}/{tool_name}")
            else:
                # 跳过该工具执行
                return False
        # logger.info(f"[+] {tool_name} finished: {target}")
        # 对结果处理，不在links_set的就存储到link.csv中
        if os.path.exists(f'{output_folder}/{output_filename}'):
            with open(f'{output_folder}/{output_filename}', 'r', encoding="utf-8", errors='ignore') as f:
                for line in f.readlines():
                    line = line.strip()
                    url = re.sub('.*? - ', '', line)
                    if url not in links_set:
                        # data = f'GET,{url},,'
                        data = [tool_name, "GET", url, "", ""]
                        urls_data_tmp_to_csv.append(data)
                        urls_set_tmp.add(url)
                        links_set.add(url)  # links_set 增加新的

            # 差集发送给xray,攻击模式端口没,则只收集跳过发送给xray的攻击扫描
            to_xray(urls_set_tmp, attackflag=attackflag, fromurl=target)

            # 存储gospider 爬取到的url method headers body
            # with open(f"{root}/result/{date}/{domain}.links.csv", "a", encoding="utf-8") as f1:
            to_csv(f"result/{date}/{domain}.links.csv", urls_data_tmp_to_csv, mmode='a')
        else:
            logger.error(f'[-] gospider not found {output_folder}/{output_filename}')
        logger.info(f"[+] {tool_name} finished: {target}")

    @logger.catch
    def hakrawler(data1, attackflag=attackflag):
        '''
        hakrawler v 2.1 exe路径要为\反斜杠
        hakrawler.exe -u http://testphp.vulnweb.com/
        :param data1: 需要带http
        :param attackflag:
        :return:
        '''
        tool_name = str(sys._getframe().f_code.co_name)
        logger.info('<' * 10 + f'start {tool_name}' + '>' * 10)

        # 创建多个子域名结果输出文件夹
        output_folder = f'{sensitiveinfo_log_folder}/{tool_name}_log'
        makedir0(output_folder)

        target = data1
        subdomain_tuple = tldextract.extract(target)
        subdomain = '.'.join(part for part in subdomain_tuple if part)  # www_baidu_com
        urls_data_tmp_to_csv = []
        urls_set_tmp = set()
        # 结果文件名 xx_xx_xx 结果是指定文件夹
        cmdstr = f'{pwd}\\hakrawler\\hakrawler{suffix} -u {target} -d 4 -subs -timeout 10 -unique'
        # cmdstr = f'{os.path.realpath(f"{pwd}/hakrawler/hakrawler{suffix}")} -u {target} -d 4 -subs -timeout 10 -unique'
        logger.info(f"[+] command:{cmdstr}")
        resultlist = __subprocess2(cmdstr)
        logger.info(f"[+] {tool_name} finished: {target}")
        # 二进制读取结果，没有生成文件,后面将结果存储起来
        # 对结果处理，不在links_set的就存储到link.csv中
        for i in resultlist:
            url = i.decode().strip()
            if url not in links_set:
                # data = f'GET,{url},,'
                data = [tool_name, "GET", url, "", ""]
                urls_data_tmp_to_csv.append(data)
                urls_set_tmp.add(url)
                links_set.add(url)

        # 差集发送给xray,攻击模式端口没,则只收集跳过发送给xray的攻击扫描
        to_xray(urls_set_tmp, attackflag=attackflag, fromurl=target)

        # 对结果处理,新增的,不是扫描的全部结果,是剔除links_set之后的url,将结果存储到txt中
        with open(f'{output_folder}/{subdomain}.{tool_name}.txt', 'w', encoding='utf-8',
                  errors='ignore') as f:
            for i in urls_set_tmp:
                f.write(i + '\n')

        # 存储gospider 爬取到的url method headers body
        # with open(f"{root}/result/{date}/{domain}.links.csv", "a", encoding="utf-8") as f1:
        to_csv(f"result/{date}/{domain}.links.csv", urls_data_tmp_to_csv, mmode='a')
        logger.info(f"[+] {tool_name} finished: {target}")

    @logger.catch
    def gau(data1, attackflag=attackflag):
        '''
        gau v 2.1 2.1.2  exe路径要为\反斜杠
        gau.exe --subs --retries 2  --timeout 65 --fc 404,302 testphp.vulnweb.com --verbose --o  2.txt
        :param data1: 带不带http,都行
        :param attackflag:
        输出文件文件名不能带有冒号，否则会输出文件内容失败
        https://github.com/xnl-h4ck3r/waymore
        :return:
        '''
        tool_name = str(sys._getframe().f_code.co_name)
        logger.info('<' * 10 + f'start {tool_name}' + '>' * 10)

        # 创建多个子域名结果输出文件夹
        output_folder = f'{sensitiveinfo_log_folder}/{tool_name}_log'
        makedir0(output_folder)

        # target = urlsplit(data1)[1]
        target = data1
        subdomain_tuple = tldextract.extract(data1)
        subdomain = '.'.join(part for part in subdomain_tuple if part)  # www_baidu_com

        urls_data_tmp_to_csv = []
        urls_set_tmp = set()
        # 结果文件名 xx_xx_xx 结果是指定文件夹
        cmdstr = f'{pwd}/gau/gau{suffix} --subs --retries 2 --fc 404,302 --verbose --o {output_folder}/{subdomain}.{tool_name}.txt {target}'
        logger.info(f"[+] command:{cmdstr}")
        # __subprocess1(cmdstr, timeout=None, path=f"{pwd}/{tool_name}")
        runtime = all_config['tools']['sensitiveinfo'][tool_name]['runtime']
        # 如果runtime为空则不限时，如果为0 则跳过该工具执行，如果为指定数字则限时执行
        if runtime is None:
            __subprocess1(cmdstr, timeout=None, path=f"{pwd}/{tool_name}")
        else:
            runtime = int(runtime)
            if runtime != 0:
                __subprocess1(cmdstr, timeout=runtime, path=f"{pwd}/{tool_name}")
            else:
                # 跳过该工具执行
                return False
        # logger.info(f"[+] {tool_name} finished: {target}")
        if os.path.exists(f'{output_folder}/{subdomain}.{tool_name}.txt'):
            with open(f'{output_folder}/{subdomain}.{tool_name}.txt', 'r', encoding='utf-8') as f:
                for line in f.readlines():
                    line = line.strip()
                    if line not in links_set:
                        data = [tool_name, "GET", line, "", ""]
                        urls_data_tmp_to_csv.append(data)
                        urls_set_tmp.add(line)
                        links_set.add(line)  # links_set 增加新的
            # 差集发送给xray,攻击模式端口没,则只收集跳过发送给xray的攻击扫描
            to_xray(urls_set_tmp, attackflag=attackflag, fromurl=target)

            # 存储gospider 爬取到的url method headers body
            # with open(f"{root}/result/{date}/{domain}.links.csv", "a", encoding="utf-8") as f1:
            to_csv(f"result/{date}/{domain}.links.csv", urls_data_tmp_to_csv, mmode='a')
        else:
            logger.error(f'{tool_name} not found {output_folder}/{subdomain}.{tool_name}.txt')
        logger.info(f"[+] {tool_name} finished: {target}")

    # 暂时先不用，还未完成，带主动性为 dirsearch 200的结果给xray
    @logger.catch
    def dirsearch(data1):
        '''
        dirsearch v0.4.2.6
        :param data1:
        :return:
        '''
        tool_name = str(sys._getframe().f_code.co_name)
        logger.info('<' * 10 + f'start {tool_name}' + '>' * 10)
        target = data1
        urls_tmp = []
        # 将dirsearch扫出的url添加到xray去 -x 301,302,403,404,405,500,501,502,503 -r -R 3 --crawl
        cmdstr = f'python3 {pwd}/dirsearch/dirsearch.py -x 403,404 -u {target} --full-url -t 10 --random-agent --format csv -o {sensitiveinfo_log_folder}/{domain}.{tool_name}.csv'
        logger.info(f"[+] command:{cmdstr}")
        os.system(cmdstr)
        # cmd = cmdstr.split(' ')
        # output = __subprocess(cmd)
        # print("".join(output).encode())
        print(f"[+] {target} dirsearch finished")
        # 将200的url找出来
        with open(f"{sensitiveinfo_log_folder}/{domain}.{tool_name}.csv", "r") as f:
            reader = csv.reader(f)
            head = next(reader)
            for row in reader:
                if len(row) != 0:
                    if row[1] == "200":
                        urls_tmp.append("GET " + row[0])
                    elif row[1] == "301":
                        urls_tmp.append("GET " + row[4])
        # 将links记录到 result/{date}/{domain}.links.txt中
        with open(f"result/{date}/{domain}.links.txt", "a", encoding="utf-8") as f1:
            for i in urls_tmp:
                f1.write(i + "\n")

    # 暂时先不用，没有代理池，dork文件如何处理也没写完，通过google查询某域名的敏感文件
    @logger.catch
    def urlcollector(data1):
        '''
        url-collector 20220908  exe路径
        :param data1: 需要带http
        :param attackflag:
        :return:
        '''
        tool_name = str(sys._getframe().f_code.co_name)
        logger.info('<' * 10 + f'start {tool_name}' + '>' * 10)
        # 代理端口没开跳过
        if checkport(10809) is False:
            logger.error("proxy port 10809 not open!")
            return

        # 创建多个子域名结果输出文件夹
        output_folder = f'{sensitiveinfo_log_folder}/{tool_name}_log'
        makedir0(output_folder)

        target = data1
        subdomain_tuple = tldextract.extract(data1)
        subdomain = '.'.join(part for part in subdomain_tuple if part)  # www_baidu_com
        urls_data_tmp = []
        urls_set_tmp = set()
        # 结果文件名 xx_xx_xx 结果是指定文件夹
        # url-collector.exe -e baidu -k "1111" -o 1.txt
        # 如下都得修改
        dorkfile = f'{pwd}/dorks.txt'
        cmdstr = f'{pwd}/urlcollector/urlcollector{suffix} -i {dorkfile} -o {output_folder}/{domain}.txt --routine-count 5 --proxy "http://127.0.0.1:10809"'
        logger.info(f"[+] command:{cmdstr}")
        resultlist = __subprocess2(cmdstr)
        logger.info(f"[+] {tool_name} finished: {target}")
        # 二进制读取结果，没有生成文件
        # 对结果处理，不在links_set的就存储到link.csv中
        for i in resultlist:
            url = i.decode().strip()
            urls_set_tmp.add(url)
            if url not in links_set:
                data = f'GET,{url},,'
                urls_data_tmp.append(data)
                links_set.add(url)
                if attackflag:
                    if checkport(Xray_Port):
                        request0({"method": "GET", "url": url, "headers": "", "data": ""})
                    else:
                        logger.error(f"xray not running on {Xray_Port}! skip to xray attack!")
        # 对结果处理,将结果存储到txt中
        with open(f'{output_folder}/{subdomain}.txt', 'w', encoding='utf-8', errors='ignore') as f:
            for i in urls_set_tmp:
                f.write(i + '\n')

        # 存储gospider 爬取到的url method headers body
        # with open(f"{root}/result/{date}/{domain}.links.csv", "a", encoding="utf-8") as f1:
        with open(f"result/{date}/{domain}.links.csv", "a", encoding="utf-8") as f1:
            for i in urls_data_tmp:
                f1.write(i + "\n")

    def run():
        # if domain and url is None and urlsfile is None:
        # if len(all_config["domain"]["scanned_targets"]):
        # if isdomain:
        #     emailall(domain)
        # urlsfile = f"result/{date}/{domain}.subdomains.with.http.txt"
        target = domain if domain else hashlib.md5(bytes(date, encoding='utf-8')).hexdigest()
        with open(urlsfile, "r", encoding="utf-8") as f:
            for url in f.readlines():
                url = url.strip()
                print(url)
                if progress_record(date=date, target=target, subtarget=url, module="sensitiveinfo",
                                   finished=False) is False:
                    crawlergo(url, attackflag=attackflag)
                    rad(url, attackflag=attackflag)
                    hakrawler(url, attackflag=attackflag)
                    gospider(url, attackflag=attackflag)
                    gau(url, attackflag=attackflag)
                    URLFinder(url, attackflag=attackflag)
                    # urlcollector('未完成')
                    links_set.clear()
                    # dirsearch(url.strip())
                    progress_record(date=date, target=target, subtarget=url, module="sensitiveinfo", finished=True)
        logger.info('-' * 10 + f'finished {sys._getframe().f_code.co_name}' + '-' * 10)

    run()


@logger.catch
def run(url=None, urlfile=None, attack=False, date=None):
    '''
    usage:

        python main.py --url xxx.com
        python main.py --urlfile urls.txt
        python main.py --url xxx.com --attack True  记得开xray监听

    :param str  url:     One url
    :param str  urlfile:    File path of urlsfile per line
    :return:
    '''
    create_logfile()
    import datetime
    date1 = str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
    date = date if date else date1
    if url and urlfile is None:
        manager(domain=None, url=url, urlsfile=None, attackflag=attack, date=date)
    elif urlfile and url is None:
        if os.path.exists(urlfile):
            manager(domain=None, url=None, urlsfile=urlfile, attackflag=attack, date=date)
        else:
            logger.error(f'{urlfile} not found!')
    else:
        logger.error("Please check --url or --urlfile\nCheck that the parameters are correct.")


if __name__ == '__main__':
    fire.Fire(run)
    # manager("tiqianle.com", date="2022-09-02-00-01-39")
    # manager(domain="vulweb.com",url=None,urlsfile=None,attackflag=False, date="2022-09-02-00-01-39")
    # print(tools_config)
