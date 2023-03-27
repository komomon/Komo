#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author:Komomon
# @Time:2023/1/8 20:03


import csv
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import traceback
from urllib.parse import urlparse
import fire
from termcolor import cprint
import os
from loguru import logger
from common.functions import *


def create_logfile():
    if os.path.exists(f'{os.getcwd()}/log') is False:
        os.makedirs(f'{os.getcwd()}/log')
    logger.add(sink='log/runtime.log', level='INFO', encoding='utf-8')
    logger.add(sink='log/error.log', level='ERROR', encoding='utf-8')


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
def progress_record(date=None, target=None, module="survivaldetect", value=None, finished=False):
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


def __aaaa():
    pass


@logger.catch
class manager():
    '''
    不包括单个url的情况
    urlsfile 为子域名，不带http
    '''

    def __init__(self, domain=None, subdomain=None, subdomains=None, date="2022-09-02-00-01-39"):
        logger.info('\n' + '<' * 18 + f'start {__file__}' + '>' * 18)
        self.domain = domain
        self.subdomain = subdomain
        self.subdomains = subdomains
        self.date = date
        self.suffix = SUFFIX
        self.root = os.getcwd()
        self.pwd_and_file = os.path.abspath(__file__)
        self.pwd = os.path.dirname(self.pwd_and_file)  # E:\ccode\python\006_lunzi\core\tools\domain
        # 获取当前目录的前三级目录，即到domain目录下，来寻找exe domain目录下
        self.grader_father = os.path.abspath(os.path.dirname(self.pwd_and_file) + os.path.sep + "../..")
        # 创建存储子域名工具扫描结果的文件夹
        self.module_log_folder = f"result/{date}/survivaldetectlog"
        if os.path.exists(self.module_log_folder) is False:
            os.makedirs(self.module_log_folder)

        # 匹配输入文件
        self.input_file = ""
        self.output_filename_prefix = ""
        # print(domain, subdomain, subdomains)
        if self.domain and self.subdomain is None and self.subdomains is None:
            ipport_and_domain_list = []  # 暂存ipport 和有cdn的域名合并起来来探活
            # input_file = f'result/{self.date}/{domain}.final.subdomains.txt'
            self.input_file = f"result/temp/{self.domain}.ipport_and_domain.txt"
            input_file1 = f"result/{self.date}/{self.domain}.ports.txt"
            input_file2 = f"result/{self.date}/{self.domain}.cdn.subdomains.txt"
            input_file3 = f"result/{self.date}/{self.domain}.errorcdn.subdomains.txt"
            input_file_list = [input_file1, input_file2, input_file3]
            for file in input_file_list:
                if os.path.exists(file):
                    with open(file, 'r', encoding="utf-8") as f:
                        for line in f.readlines():
                            line = line.strip()
                            if line:
                                ipport_and_domain_list.append(line)
            with open(self.input_file, "w", encoding="utf-8") as g:
                for i in ipport_and_domain_list:
                    g.write(i+"\n")
            self.output_filename_prefix = domain
            if os.path.exists(self.input_file) is False or os.path.getsize(self.input_file) is False:
                logger.info(f"[+] {self.input_file} not found, exit!")
                # return False
        elif self.subdomains and self.domain is None and self.subdomain is None:
            if os.path.exists(self.subdomains):
                self.input_file = self.subdomains
                # 如果从文件输入则结果以时间为文件名
                self.output_filename_prefix = self.date
            else:
                logger.error(f'{self.subdomains} not found!')
                exit(1)
        elif self.subdomain and self.domain is None and self.subdomains is None:
            self.input_file = f"temp.subdomains.txt"
            self.output_filename_prefix = self.date
            # print(3,domain,file)
            # subdomain_tuple = tldextract.extract(url)
            # output_filename_prefix = '.'.join(part for part in subdomain_tuple if part)  # www.baidu.com 127_0_0_1
            with open(self.input_file, "w", encoding="utf-8") as f:
                f.write(self.subdomain)
        else:
            logger.error(f'[-] Please check subdomain or subdomains or domain')
            exit(1)

    # 生成带http的域名url 和ip文件 result/{date}/{domain}.subdomains_with_http.txt result/{date}/{domain}.subdomains_ips.txt
    @logger.catch
    def httpx(self, domain=None, subdomain=None, subdomains=None):
        '''
        httpx 1.2.4
        输入是子域名文件，可以带http可以不带，主要为了进行域名探活
        httpx输出的文件夹名称不能用下划线
        :return:
        '''
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)
        # logger.info('<' * 10 + f'start {tool_name}' + '>' * 10)
        # output_folder = f"result/{date}/{sys._getframe().f_code.co_name}log"  # result/{date}/httpxlog
        output_folder = f'{self.module_log_folder}/{sys._getframe().f_code.co_name}log'
        if os.path.exists(output_folder) is False:
            os.makedirs(output_folder)
        # input_file = ""
        # output_filename_prefix = ""
        # print(domain, subdomain, subdomains)
        # if domain and subdomain is None and subdomains is None:
        #     # input_file = f'result/{self.date}/{domain}.final.subdomains.txt'
        #     input_file = f"result/{self.date}/{domain}.ports.txt"
        #     output_filename_prefix = domain
        #     if os.path.exists(input_file) is False or os.path.getsize(input_file) is False:
        #         logger.info(f"[+] {input_file} not found, exit!")
        #         return False
        # elif subdomains and domain is None and subdomain is None:
        #     if os.path.exists(subdomains):
        #         input_file = subdomains
        #         # 如果从文件输入则结果以时间为文件名
        #         output_filename_prefix = self.date
        #     else:
        #         logger.error(f'{subdomains} not found!')
        #         exit(1)
        # elif subdomain and domain is None and subdomains is None:
        #     input_file = f"temp.{sys._getframe().f_code.co_name}.txt"
        #     output_filename_prefix = self.date
        #     # print(3,domain,file)
        #     # subdomain_tuple = tldextract.extract(url)
        #     # output_filename_prefix = '.'.join(part for part in subdomain_tuple if part)  # www.baidu.com 127_0_0_1
        #     with open(input_file, "w", encoding="utf-8") as f:
        #         f.write(subdomain)
        # else:
        #     logger.error(f'[-] Please check subdomain or subdomains or domain')
        #     exit(1)

        subdomains_with_http = []
        subdomains_ips_tmp = []
        subdomains_ips = []
        output_file = f"{output_folder}/{self.output_filename_prefix}.{sys._getframe().f_code.co_name}.csv"
        # -favicon
        # -tech-detect	显示基于Wappalyzer数据集的技术
        # -cname
        # -cdn	display cdn in use
        # -x string	request methods to probe, use 'all' to probe all HTTP methods
        # -ec, -exclude-cdn	skip full port scans for CDNs (only checks for 80,443)
        # -td, -tech-detect	display technology in use based on wappalyzer dataset
        # -http-proxy, -proxy string    http proxy to use (eg http://127.0.0.1:8080)
        cmdstr = f'{self.pwd}/httpx/httpx{self.suffix} -l {self.input_file} -status-code -title -favicon -ip -no-color -csv -o {output_file}'
        # cmdstr = "ping 127.0.0.1"
        logger.info(f"[+] command:{cmdstr}")
        os.system(cmdstr)
        # 结果处理，生成带http的文件和ip文件
        if os.path.exists(output_file):
            logger.info(
                f"[+] Generate file: {output_folder}/{self.output_filename_prefix}.{sys._getframe().f_code.co_name}.csv")
            # 生成带http的url
            with open(f"{output_folder}/{self.output_filename_prefix}.{sys._getframe().f_code.co_name}.csv", 'r',
                      errors='ignore') as f:
                reader = csv.reader(f)
                head = next(reader)
                for row in reader:
                    obj = urlparse(row[8].strip())
                    # ParseResult(scheme='https', netloc='www.google.com:8080', path='/search', params='', query='newwindow=1&biw=1091&bih=763', fragment='')
                    subdomains_with_http.append(f"{obj.scheme}://{obj.netloc}")  # url
                    subdomains_ips_tmp.append(row[18].strip())  # host
                subdomains_ips = getips(list(set(subdomains_ips_tmp)))
            # 生成带http的url txt
            with open(f"result/{self.date}/{self.output_filename_prefix}.subdomains.with.http.txt", "w",
                      encoding="utf-8") as f2:
                f2.writelines("\n".join(subdomains_with_http))
            logger.info(f"[+] Generate file: result/{self.date}/{self.output_filename_prefix}.subdomains.with.http.txt")
            progress_file_record(date=self.date, filename="subdomain_with_http_file",
                                 value=f"result/{self.date}/{self.output_filename_prefix}.subdomains.with.http.txt")
            # # 生成子域名对应的ip txt
            # with open(f"result/{self.date}/{output_filename_prefix}.subdomains.ips.txt", "w", encoding="utf-8") as f3:
            #     f3.writelines("\n".join(subdomains_ips))
            # logger.info(f"[+] Generate file: result/{self.date}/{output_filename_prefix}.subdomains.ips.txt")
            # 最后移除临时文件
            # if subdomain and domain is None and subdomains is None:
            #     if os.path.exists(self.input_file):
            #         os.remove(self.input_file)
        else:
            logger.error(f"[+] {output_file} does not exist.")
            exit(1)

    # run只为了方便顺序执行和规定流程执行的时候查看进度记录来判断跟进进度。
    def run(self):
        target = self.domain if self.domain else hashlib.md5(bytes(self.date, encoding='utf-8')).hexdigest()
        if progress_record(date=self.date, target=target, module="survivaldetect", finished=False) is False:
            # 如何存在所需的文件则扫描，否则不扫描
            if os.path.exists(self.input_file):
                if os.path.getsize(self.input_file):
                    self.httpx(domain=self.domain, subdomain=self.subdomain, subdomains=self.subdomains)
                else:
                    logger.error(f"[+] {self.input_file} size is 0, Skip survivaldetect module!")
            else:
                logger.error(f"[+] {self.input_file} not found, Skip survivaldetect module!")
            progress_record(date=self.date, target=target, module="survivaldetect", finished=True)
        logger.info('-' * 10 + f'finished {sys._getframe().f_code.co_name}' + '-' * 10)
        # if exit_flag: exit(1)
    # def run(self):
    #     target = self.domain if self.domain else hashlib.md5(bytes(self.date, encoding='utf-8')).hexdigest()
    #     if progress_record(date=self.date, target=target, module="survivaldetect", finished=False) is False:
    #         self.httpx(domain=self.domain, subdomain=self.subdomain, subdomains=self.subdomains)
    #         progress_record(date=self.date, target=target, module="survivaldetect", finished=True)
    #     logger.info('-' * 10 + f'finished {sys._getframe().f_code.co_name}' + '-' * 10)


@logger.catch
def run(subdomain=None, subdomains=None, date=None):
    '''
    usage:

        python main.py --subdomain xxx.com
        python main.py --subdomains urls.txt

    :param str  subdomain:     One subdomain
    :param str  subdomains:    File path of subdomainfile per line
    :return:
    '''
    create_logfile()
    import datetime
    date1 = str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
    date = date if date else date1
    if any([subdomain, subdomains]):
        bot = manager(domain=None, subdomain=subdomain, subdomains=None, date=date)
        bot.run()
    else:
        logger.error("Please check --subdomain or --subdomains\nCheck that the parameters are correct.")


if __name__ == '__main__':
    fire.Fire(run)
    # import datetime
    # date = str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
    # manager(domain="tiqianle.com",url=None,urlsfile=None, date="2022-09-02-00-01-39")
    # manager(domain=None,url=None, urlsfile="subdomains.txt", date="2022-09-02-00-01-39")
