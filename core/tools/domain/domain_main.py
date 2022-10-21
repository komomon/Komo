#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time:2022/9/1 14:35
import csv
import inspect
import json
import os
import shutil
import subprocess
import traceback
import fire
from loguru import logger
import sys
import dns
import tldextract


def create_logfile():
    if os.path.exists(f'{os.getcwd()}/log') is False:
        os.makedirs(f'{os.getcwd()}/log')
    logger.add(sink='log/runtime.log', level='INFO', encoding='utf-8')
    logger.add(sink='log/error.log', level='ERROR', encoding='utf-8')


def checkPanAnalysis(domain):
    logger.info('-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
    panDomain = 'sadfsadnxzjlkcxjvlkasdfasdf.{}'.format(domain)
    try:
        dns_A_ips = [j for i in dns.resolver.query(panDomain, 'A').response.answer for j in i.items]
        print(dns_A_ips)
        logger.error('[PanAnalysis] {} -> {}'.format(panDomain, dns_A_ips))
        return True
    except Exception as e:
        logger.info('[Not PanAnalysis] :{}'.format(e.args))
        return False


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


# 打印脚本跑出了几个新的子域名，并返回最新最全的子域名列表  传递两个列表，old是前面收集好的子域名，new是刚跑完的脚本收集的子域名，进行比较.
def printGetNewSubdomains(old_subdomains, new_subdomains):
    if len(old_subdomains) > 0:
        newSubdomains = list(set(new_subdomains) - set(old_subdomains))
        print('[new :{}] {}'.format(len(newSubdomains), newSubdomains))
    return list(set(new_subdomains + old_subdomains))


# 每个函数的结果都存到 result/{date}/domain_log下
# 装饰器
def additional(func1):
    def init2():
        logger.info(f'[+] start {func1.__qualname__}')
        func1()
        logger.info(f'[+] finish {func1.__qualname__}')

    return func1
    # pass


# 过程记录文件初始化
def progress_init(date=None, targets: list = []):
    logfile = f'result/{date}/{date}_log.json'
    log = {
        "scan_list": targets,
        "scanned_target": [],
        "scanning_target": "",
        "domain_scan": False,
        "finger": False,
        "portscan": False,
        "sensitiveinfo": False,
        "vulscan": False

    }
    if os.path.exists(logfile) is False:
        with open(logfile, 'w', encoding='utf-8') as f:
            f.write(json.dumps(log))
        logger.info(f'Create logjson: {logfile}')


# 更新过程记录
def progress_control(module: str = None, target: str = None, finished: bool = False, date: str = None):
    logfile = f'result/{date}/{date}_log.json'
    if os.path.exists(logfile) is False:
        logger.error(f'{logfile} not found! Exit.')
        exit(1)
    with open(logfile, 'r', encoding='utf-8') as f1:
        log_json = json.loads(f1.read())

    if module in dict(log_json).keys():
        if finished:
            log_json[module] = True
        elif finished is False and target:
            log_json['scan_list'].remove(target)
            log_json['scanned_target'].append(target)
            if len(log_json['scan_list']) != 0:
                log_json['scanning_target'] = log_json[0]

        with open(logfile, 'w', encoding='utf-8') as f2:
            f2.write(json.dumps(log_json))
    else:
        logger.error(f'The supplied [{module}] does not exist!')

    return log_json['scanning_target']


# 启用子进程执行外部shell命令
@logger.catch
def __subprocess1(cmd, timeout=None, path=None):
    '''
    rad 不支持结果输出到管道所以stdout=None才可以，即默认不设置
    :param cmd:
    :param timeout:
    :param path:
    :return:
    '''
    if isinstance(cmd, str):
        cmd = cmd.split(' ')
    elif isinstance(cmd, list):
        cmd = cmd
    else:
        logger.error(f'[-] cmd type error,cmd should be a string or list: {cmd}')
        return
    try:
        # logger.info(f"[+] command:{' '.join(cmd)}")
        p = subprocess.Popen(cmd, shell=True, cwd=path)
        # p = subprocess.Popen(cmd, shell=True,cwd=path,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if timeout:
            p.wait(timeout=timeout)
        else:
            p.wait()

    except Exception as e:
        logger.error(traceback.format_exc())
        # logger.error(f'{sys._getframe().f_code.co_name} Reach Set Time and exit')
    finally:
        f_name = inspect.getframeinfo(inspect.currentframe().f_back)[2]
        logger.info(f'{f_name} finished.')


# @progress_control(module="domain_scan",date=date)
@logger.catch
def manager(domain=None, date="2022-09-02-00-01-39"):
    subdomains = list()  # 用于存储最后的子域名结果
    subdomains_tmp = list()
    suffix = get_system()
    root = os.getcwd()
    pwd_and_file = os.path.abspath(__file__)
    pwd = os.path.dirname(pwd_and_file)

    # 获取当前目录的前三级目录，即到domain目录下，来寻找exe domain目录下
    grader_father = os.path.abspath(os.path.dirname(pwd_and_file) + os.path.sep + "../..")

    subdomains_log_folder = f"result/{date}/domain_log"
    if os.path.exists(subdomains_log_folder) is False:
        os.makedirs(subdomains_log_folder)
    if os.path.exists(f"result/temp/") is False:
        os.makedirs(f"result/temp/")

    # 执行命令
    @logger.catch
    def runcmd(toolname, cmd, subdomain_file):
        '''
        运行命令，如果工具执行结果文件只包含子域名，则从文件提取子域名，存到subdomains->list
        如果工具执行结果文件不只是包含子域名，比如amass输出的是json，则在工具对应函数自行从结果文件提取子域名，存到subdomains->list
        :param cmd:
        :return:
        '''
        # global subdomains
        logger.info('-' * 10 + f'start {str(toolname)}' + '-' * 10)
        logger.info(f"[+] command:{cmd}")
        os.system(cmd)
        # __subprocess1(cmd=cmd,timeout=15)
        if os.path.exists(subdomain_file):
            with open(subdomain_file, 'r', encoding='utf-8') as fd:
                for line in fd.readlines():
                    subdomains_tmp.append(line.strip())
            subdomains.extend(list(set(subdomains_tmp)))

    # 调用amass 结果输出到json
    @logger.catch
    def amass():
        '''
        amass v3.19.3
        :return:
        '''
        output_filename = f"{subdomains_log_folder}/{domain}.{sys._getframe().f_code.co_name}.json"
        # cmdstr = f'{pwd}/amass/amass{suffix} enum -active -brute -min-for-recursive 2 -d {domain} -json {output_filename}'
        cmdstr = f'{pwd}/amass/amass{suffix} enum -active -brute -max-depth 3 -d {domain} -json {output_filename}'  # 三层有点慢
        # cmdstr = f'{pwd}/amass/amass{suffix} enum -active -brute -d {domain} -json {output_filename}'
        runcmd(sys._getframe().f_code.co_name, cmdstr, "")
        # 输出文件内容不只是域名的话则需要自行处理，提取子域名，然后转储
        with open(output_filename, 'r', encoding='utf-8') as fd:
            for line in fd.readlines():
                amass_data = json.loads(line.strip())
                if 'name' in amass_data:
                    subdomains_tmp.append(amass_data['name'])
        subdomains.extend(list(set(subdomains_tmp)))

    # 调用ksubdomain 结果输出到txt
    @logger.catch
    def ksubdomain():
        '''
        ksubdomain
        结果：{subdomains_log_folder}/{domain}-{sys._getframe().f_code.co_name}.txt
        :return:
        '''
        # logger.info('-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
        output_filename = f'{subdomains_log_folder}/{domain}.{sys._getframe().f_code.co_name}.txt'
        cmdstr = f"{pwd}/ksubdomain/ksubdomain{suffix}  enum --band 5M --domain {domain} --silent --only-domain --level 2 --output {output_filename}"
        runcmd(sys._getframe().f_code.co_name, cmdstr, output_filename)


    # 水泽 暂时先不要，主要就是为了用他的搜索引擎部分，可以看改的源码
    @logger.catch
    def ShuiZe():
        logger.info('-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
        cmd = "python3 " + pwd + f"/ShuiZe/ShuiZe.py   -d {domain} --justInfoGather 1 --output result/{date}/domain_log/{domain}.ShuiZe.txt"
        # print(f"[+] command:{cmd}")
        logger.info(f"[+] command:{cmd}")
        os.system(cmd)
        with open(f"result/{date}/{domain}.ShuiZe.txt", 'r', encoding='utf-8') as fd:
            for line in fd.readlines():
                subdomains_tmp.append(line.strip())
            # subdomains.extend()
        subdomains.extend(list(set(subdomains_tmp)))
        # print(subdomains)

    @logger.catch
    def dnsx():
        '''
        dnsx-子域名判断存活,反查A记录,支持dns查询和暴力破解，支持c段反查域名，域名探活
        :return:
        '''
        pass
        # dnsx -silent -d facebook.com -w dns_worldlist.txt
        # dnsx -silent -list xx.txt  域名探活

    @logger.catch
    def ctfr():
        '''
         ctfr zijigaixie
        :return:
        '''
        # logger.info('-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
        output_filename = f"{subdomains_log_folder}/{domain}.{sys._getframe().f_code.co_name}.txt"
        cmdstr = f"python3 {pwd}/ctfr/ctfr.py  --domain {domain} --output {output_filename}"
        runcmd(sys._getframe().f_code.co_name, cmdstr, output_filename)

    @logger.catch
    def subfinder():
        '''
        subfinder v2.5.3
        :return:
        '''
        # logger.info('-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
        output_filename = f"{subdomains_log_folder}/{domain}.{sys._getframe().f_code.co_name}.txt"
        cmdstr = f"{pwd}/subfinder/subfinder{suffix}  -d {domain} -all -no-color -o {output_filename}"
        runcmd(sys._getframe().f_code.co_name, cmdstr, output_filename)


    # 最后调用oneforall,同时将所有其他文件的结果发给oneforall，即subdomains->list 中的子域名
    @logger.catch
    def oneforall():
        '''
        oneforall 0.4.2.6
        :return:
        '''
        logger.info('-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
        if os.path.exists(f"result/{date}/oneforall_log") is False:
            os.makedirs(f"result/{date}/oneforall_log")
        cmdstr = f"python3 {pwd}/OneForAll/oneforall.py --target {domain} --path result/{date}/oneforall_log/{domain}.{sys._getframe().f_code.co_name}.csv run"
        logger.info(f"[+] command:{cmdstr}")
        os.system(cmdstr)


    # 整合各个工具扫出的子域名结果,除了oneforall
    @logger.catch
    def merge_other_tools_result():
        '''
        整合各个工具扫出的子域名结果,除了oneforall
        :return:
        '''
        subdomains_list = list(set(subdomains))
        with open(f"result/{date}/{domain}.many.tools.subdomain.txt", 'w', encoding='utf-8') as fd:
            fd.writelines("\n".join(subdomains_list))
        logger.info(f'[+] Many tools find subdomains number: {len(subdomains_list)}')
        logger.info(f'[+] Many tools find subdomains outputfile: result/{date}/{domain}.many.tools.subdomain.txt')
        # 将所有工具的结果cp到/result/temp目录下，供oneforall采集
        shutil.copy(f"result/{date}/{domain}.many.tools.subdomain.txt",
                    f"result/temp/{domain}.many.tools.subdomain.txt")
        # logger.error(f'result/{date}/{domain}.many.tools.subdomain.txt not exist!!!')

    # 将结果合并到一起 result/{date}/{domain}_final_subdomains.txt
    @logger.catch
    def merge_result():
        subdomains_list = []
        other_subdomains_list = []
        # subdomains_ips = []
        oneforall_output_filename = f"result/{date}/oneforall_log/{domain}.oneforall.csv"
        if os.path.exists(oneforall_output_filename):
            with open(oneforall_output_filename, 'r') as fd1:
                reader = csv.reader(fd1)
                head = next(reader)
                for row in reader:
                    subdomains_list.append(row[5])
                    # subdomains_ips.append(row)
        subdomains_list = list(set(subdomains_list))
        for ssubdomain in subdomains_list:
            # ExtractResult(subdomain='www', domain='worldbank', suffix='org.kg')
            subdomain_tuple = tldextract.extract(ssubdomain)
            if domain != subdomain_tuple.domain+'.'+subdomain_tuple.suffix:
                other_subdomains_list.append(ssubdomain)
                subdomains_list.remove(ssubdomain)
        with open(f"result/{date}/{domain}.final.subdomains.txt", 'w', encoding='utf-8') as fd2:
            fd2.writelines("\n".join(subdomains_list))
        with open(f"result/{date}/{domain}.other.subdomains.txt", 'w', encoding='utf-8') as fd3:
            fd3.writelines("\n".join(other_subdomains_list))
        logger.info(f'[+] Final find subdomains number: {len(subdomains_list)}')
        logger.info(f'[+] Final find subdomains outputfile: result/{date}/{domain}.final.subdomains.txt')

    def run():
        if checkPanAnalysis(domain) is False:
            # 调用那些子域名工具
            amass()
            # ksubdomain()
            ## ShuiZe()
            ## dnsx()
            subfinder()  # 被动dns扫描
            ctfr()
            # 汇总以上函数结果，合到txt中，注意上面的如果不执行
            merge_other_tools_result()
            oneforall()
            # 整合结果输出最终子域名文件 result/{date}/{domain}_final_subdomains.txt
            merge_result()
        else:
            logger.error(f"PanAnalysis: {domain}")

    run()


@logger.catch
def run(domain=None, domains=None, date=None):
    '''
    usage:

        python main.py --domain xxx.com
        python main.py --domains domains.txt

    :param str  domain:     One domain (target or targets must be provided)
    :param str  domains:    File path of one domain per line
    :return:
    '''
    create_logfile()
    import datetime
    date1 = str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
    date = date if date else date1
    if domain and domains is None:
        manager(domain=domain, date=date)
    elif domains and domain is None:
        if os.path.exists(domains):
            with open(domains, 'r', encoding='utf-8') as f:
                for domain in f.readlines():
                    manager(domain=domain, date=date)
        else:
            logger.error(f'{domains} not found!')
    else:
        logger.error("Please check --domain or --domains\nCheck that the parameters are correct")


if __name__ == '__main__':
    fire.Fire(run)

