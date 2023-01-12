#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author:Komomon
# @Time:2023/1/8 20:03


import csv
import json
import re
import shutil
import subprocess
import sys
import tempfile
import traceback

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
def progress_record(date=None, target=None, module=None, value=None, finished=False):
    logfile = f"result/{date}/log.json"
    if os.path.exists(logfile) is False:
        shutil.copy("config/log_template.json", f"result/{date}/log.json")
        return False
    else:
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
        logger.info('-' * 10 + f'start {__file__}' + '-' * 10)
        # 创建存储子域名工具扫描结果的文件夹
        self.module_log_folder = f"result/{date}/survivaldetectlog"
        if os.path.exists(self.module_log_folder) is False:
            os.makedirs(self.module_log_folder)

    # 生成带http的域名url 和ip文件 result/{date}/{domain}.subdomains_with_http.txt result/{date}/{domain}.subdomains_ips.txt
    @logger.catch
    def httpx(self, domain=None, subdomain=None, subdomains=None):
        '''
        httpx 1.2.4
        输入是子域名文件，可以带http可以不带，主要为了进行域名探活
        httpx输出的文件夹名称不能用下划线
        :return:
        '''
        logger.info('-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
        # output_folder = f"result/{date}/{sys._getframe().f_code.co_name}log"  # result/{date}/httpxlog
        output_folder = f'{self.module_log_folder}/{sys._getframe().f_code.co_name}log'
        if os.path.exists(output_folder) is False:
            os.makedirs(output_folder)
        input_file = ""
        output_filename_prefix = ""
        if domain and subdomain is None and subdomains is None:
            input_file = f'result/{self.date}/{domain}.final.subdomains.txt'
            output_filename_prefix = domain
        elif subdomains and domain is None and subdomain is None:
            if os.path.exists(subdomains):
                input_file = subdomains
                # 如果从文件输入则结果以时间为文件名
                output_filename_prefix = self.date
            else:
                logger.error(f'{subdomains} not found!')
                exit(1)
        elif subdomain and domain is None and subdomains is None:
            input_file = f"temp.{sys._getframe().f_code.co_name}.txt"
            output_filename_prefix = self.date
            # print(3,domain,file)
            # subdomain_tuple = tldextract.extract(url)
            # output_filename_prefix = '.'.join(part for part in subdomain_tuple if part)  # www.baidu.com 127_0_0_1
            with open(input_file, "w", encoding="utf-8") as f:
                f.write(subdomain)
        else:
            logger.error(f'[-] Please check subdomain or subdomains or domain')
            exit(1)

        subdomains_with_http = []
        subdomains_ips_tmp = []
        subdomains_ips = []
        output_file = f"{output_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.csv"
        cmdstr = f'{self.pwd}/httpx/httpx{self.suffix} -l {input_file} -ip -silent -no-color -csv -o {output_file}'
        # cmdstr = "ping 127.0.0.1"
        logger.info(f"[+] command:{cmdstr}")
        os.system(cmdstr)
        # 结果处理，生成带http的文件和ip文件
        if os.path.exists(output_file):
            logger.info(f"[+] Generate file: {output_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.csv")
            # 生成带http的url
            with open(f"{output_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.csv", 'r',
                      errors='ignore') as f:
                reader = csv.reader(f)
                head = next(reader)
                for row in reader:
                    subdomains_with_http.append(row[8].strip())  # url
                    subdomains_ips_tmp.append(row[18].strip())  # host
                subdomains_ips = getips(list(set(subdomains_ips_tmp)))
            # 生成带http的url txt
            with open(f"result/{self.date}/{output_filename_prefix}.subdomains.with.http.txt", "w", encoding="utf-8") as f2:
                f2.writelines("\n".join(subdomains_with_http))
            logger.info(f"[+] Generate file: result/{self.date}/{output_filename_prefix}.subdomains.with.http.txt")
            # 生成子域名对应的ip txt
            with open(f"result/{self.date}/{output_filename_prefix}.subdomains.ips.txt", "w", encoding="utf-8") as f3:
                f3.writelines("\n".join(subdomains_ips))
            logger.info(f"[+] Generate file: result/{self.date}/{output_filename_prefix}.subdomains.ips.txt")
            # 最后移除临时文件
            if subdomain and domain is None and subdomains is None:
                if os.path.exists(input_file):
                    os.remove(input_file)
        else:
            logger.error(f"[+] {output_file} does not exist.")
            exit(1)

    # run只为了方便顺序执行和规定流程执行的时候查看进度记录来判断跟进进度。
    def run(self):
        if progress_record(date=self.date, module="survivaldetect", finished=False) is False:
            self.httpx(domain=self.domain, subdomain=self.subdomain, subdomains=self.subdomains)
            progress_record(date=self.date, module="survivaldetect", finished=True)
        logger.info('-' * 10 + f'finished {sys._getframe().f_code.co_name}' + '-' * 10)

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
