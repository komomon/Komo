import base64
import csv
import inspect
import json

import re
import subprocess
import requests
import platform
import shlex
import yaml
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
from common.functions import *
import os

# import common

all_config = getconfig()
Xray_Port = int(all_config['tools']['other']['xray']['listenport'])


def create_logfile():
    if os.path.exists(f'{os.getcwd()}/log') is False:
        os.makedirs(f'{os.getcwd()}/log')
    logger.add(sink='log/runtime.log', level='INFO', encoding='utf-8')
    logger.add(sink='log/error.log', level='ERROR', encoding='utf-8')


# 进度记录,基于json 旧版
def progress_record_old(date=None, target=None, module=None, value=None, finished=False):
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


# 进度记录,基于json
def progress_record(date=None, target=None, module="emailcollect", value=None, finished=False):
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


# 启用子进程执行外部shell命令
# @logger.catch
def subprocess111(cmd, timeout=None, path=None):
    '''
    rad 不支持结果输出到管道所以stdout=None才可以，即默认不设置
    :param cmd:
    :param timeout:
    :param path:
    :return:
    '''
    f_name = inspect.getframeinfo(inspect.currentframe().f_back)[2]
    # cmd = shlex.split(cmd)
    # 执行外部shell命令， 输出结果存入临时文件中
    logger.info(f"[+] command:{cmd}")
    p = subprocess.Popen(cmd, shell=True, cwd=path)
    # p = subprocess.Popen(cmd, shell=True,cwd=path,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        # outs, errs = p.communicate(timeout=timeout)
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired as e:
        # logger.error('{} - {} - \n{}'.format(self.domain, self.__class__.__name__, e))
        logger.error(e)
        p.kill()
        # kill_process(f_name+get_system())
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error(e)
        # logger.error(f'{sys._getframe().f_code.co_name} Reach Set Time and exit')
    finally:
        logger.info(f'{f_name} finished.')


@logger.catch
class manager:
    '''
    :param domain:
    :param date:
    :return:
    '''

    def __init__(self, domain=None, date="2022-09-02-00-01-39"):
        logger.info('\n'+'<' * 18 + f'start {__file__}' + '>' * 18)
        self.domain = domain
        self.date = date
        self.ostype = OSTYPE
        self.suffix = SUFFIX
        self.root = os.getcwd()
        self.pwd_and_file = os.path.abspath(__file__)
        self.pwd = os.path.dirname(self.pwd_and_file)  # E:\ccode\python\006_lunzi\core\tools\sensitiveinfo
        # 获取当前目录的前三级目录，即到domain目录下，来寻找exe domain目录下
        self.grader_father = os.path.abspath(os.path.dirname(self.pwd_and_file) + os.path.sep + "../..")
        # print(grader_father) # E:\ccode\python\006_lunzi\core
        # 创建存储工具扫描结果的文件夹
        self.module_log_folder = f"{self.root}/result/{self.date}/emailcollect_log"
        makedir0(self.module_log_folder)

    @logger.catch
    def emailall(self, domain=None):
        '''
        emailall 20220908  exe路径
        :param data1:
        :return:
        '''
        tool_name = str(sys._getframe().f_code.co_name)
        logger.info('<' * 10 + f'start {tool_name}' + '>' * 10)
        # 创建多个子域名结果输出文件夹
        output_folder = f'{self.module_log_folder}/{tool_name}_log'
        makedir0(output_folder)

        subdomain_tuple = tldextract.extract(domain)
        # subdomain = '_'.join(part for part in subdomain_tuple if part)  # www_baidu_com
        output_filename_prefix = subdomain_tuple.domain + '.' + subdomain_tuple.suffix
        cmdstr = f'python3 {self.pwd}/emailall/emailall.py --domain {domain} run'
        # create_logfile()
        subprocess111(cmdstr, timeout=None, path=f"{self.pwd}/{tool_name}")
        # 移动结果文件 \sensitiveinfo\emailall\result\vulweb_com\vulweb.com_All.json
        output_filename_tmp = f"{self.pwd}/{tool_name}/result/{output_filename_prefix.replace('.', '_')}/{output_filename_prefix}_All.json"
        if os.path.exists(output_filename_tmp):
            try:
                shutil.move(output_filename_tmp, output_folder)
                # 记录文件
                progress_file_record(date=self.date, filename="email_file",
                                     value=f"result/{self.date}/emailcollect_log/{tool_name}_log/{output_filename_prefix}_All.json")
            except Exception as e:
                logger.error(traceback.format_exc())
        else:
            logger.error(f'[-] {tool_name} not found {output_filename_tmp} ')

    def run(self):
        if progress_record(date=self.date, target=self.domain, module="emailcollect", finished=False) is False:
            self.emailall(domain=self.domain)
            progress_record(date=self.date, target=self.domain, module="emailcollect", finished=True)
        logger.info('-' * 10 + f'finished {sys._getframe().f_code.co_name}' + '-' * 10)


# wuyongle
@logger.catch
def run(domain=None, domains=None, date=None):
    '''
    usage:

        python main.py --domain xxx.com
    :param str  domain:     One url
    :param str  domains:    File path of domainsfile per line
    :return:
    '''
    create_logfile()
    import datetime
    date1 = str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
    date = date if date else date1
    if domain and domains is None:
        bot = manager(domain=domain, date=date)
        bot.run()
    elif domains and domain is None:
        if os.path.exists(domains):
            pass
    else:
        logger.error("Please check --domain or --domains\nCheck that the parameters are correct.")


if __name__ == '__main__':
    fire.Fire(run)
    # manager("tiqianle.com", date="2022-09-02-00-01-39")
    # manager(domain="vulweb.com",url=None,urlsfile=None,attackflag=False, date="2022-09-02-00-01-39")
    # print(tools_config)
