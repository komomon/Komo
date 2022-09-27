
import csv
import re
import subprocess
import sys
import tempfile
import traceback
from tkinter import N

import fire
from termcolor import cprint
import os
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
        # cmd = ""
        print("get system type error")
        exit(1)


@logger.catch
def __subprocess2(cmd):
    try:
        out_temp = tempfile.SpooledTemporaryFile(
            max_size=10 * 1000, mode='w+b')
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


def isexist(filepath):
    if os.path.exists(filepath):
        return True
    else:
        logger.error(f'{filepath} not found!')
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
    # iplist =
    logger.info(f'[+] ip number：{len(ips_set)}')
    return list(ips_set)


@logger.catch
def manager(domain=None, url=None, urlsfile=None, date="2022-09-02-00-01-39"):
    '''
    不包括单个url的情况
    urlsfile 为子域名，不带http
    '''
    suffix = get_system()
    root = os.getcwd()
    pwd_and_file = os.path.abspath(__file__)
    pwd = os.path.dirname(pwd_and_file)

    grader_father = os.path.abspath(
        os.path.dirname(pwd_and_file) + os.path.sep + "../..")
    logger.info('-' * 10 + f'start {__file__}' + '-' * 10)

    finger_log_folder = f"result/{date}/fingerlog"
    if os.path.exists(finger_log_folder) is False:
        os.makedirs(finger_log_folder)

    @logger.catch
    def httpx(url=url, file=urlsfile):
        '''
        httpx 1.2.4
        输入是子域名文件，可以带http可以不带，主要为了进行域名探活
        httpx输出的文件夹名称不能用下划线
        :return:
        '''
        logger.info(
            '-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
        # output_folder = f"result/{date}/{sys._getframe().f_code.co_name}log"  # result/{date}/httpxlog
        output_folder = f'{finger_log_folder}/{sys._getframe().f_code.co_name}log'
        if os.path.exists(output_folder) is False:
            os.makedirs(output_folder)
        if domain and file is None and url is None:
            file = f'result/{date}/{domain}.final.subdomains.txt'
            output_filename_prefix = domain
        elif file and domain is None and url is None:
            output_filename_prefix = date
            # domain = date
        elif url and domain is None and file is None:
            # domain = date
            file = f"temp.{sys._getframe().f_code.co_name}.txt"
            output_filename_prefix = date
            with open(urlsfile, "w", encoding="utf-8") as f:
                f.write(url)
        else:
            logger.error(f'[-] Please check file or domain')
            exit(1)

        subdomains_with_http = []
        subdomains_ips_tmp = []
        subdomains_ips = []
        cmdstr = f'{pwd}/httpx/httpx{suffix} -l {file} -ip -silent -no-color -csv -o {output_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.csv'
        logger.info(f"[+] command:{cmdstr}")
        os.system(cmdstr)
        logger.info(
            f"[+] Generate file: {output_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.csv")
        with open(f"{output_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.csv", 'r', errors='ignore') as f:
            reader = csv.reader(f)
            head = next(reader)
            for row in reader:
                subdomains_with_http.append(row[8].strip())  # url
                subdomains_ips_tmp.append(row[18].strip())  # host
            subdomains_ips = getips(list(set(subdomains_ips_tmp)))

        with open(f"result/{date}/{output_filename_prefix}.subdomains.with.http.txt", "w", encoding="utf-8") as f2:
            f2.writelines("\n".join(subdomains_with_http))
        logger.info(
            f"[+] Generate file: result/{date}/{output_filename_prefix}.subdomains.with.http.txt")
        # 生成子域名对应的ip txt
        with open(f"result/{date}/{output_filename_prefix}.subdomains.ips.txt", "w", encoding="utf-8") as f3:
            f3.writelines("\n".join(subdomains_ips))
        logger.info(
            f"[+] Generate file: result/{date}/{output_filename_prefix}.subdomains.ips.txt")
        # 最后移除临时文件
        if url and domain is None and file is None:
            if os.path.exists(file):
                os.remove(file)

    # 进行指纹识别 result/{date}/ehole_log/{domain}.ehole.xlsx

    @logger.catch
    def ehole(url=url, file=urlsfile):
        '''
        输入是带http的子域名文件
        ehole的输出文件xlsx 文件名只能有一个点,所以如下将多余的.换成了-横线
        :return:
        '''
        logger.info(
            '-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
        # 创建该工具的结果文件夹
        # output_folder = f"result/{date}/{sys._getframe().f_code.co_name}_log"
        output_folder = f'{finger_log_folder}/{sys._getframe().f_code.co_name}log'
        if os.path.exists(output_folder) is False:
            os.makedirs(output_folder)

        if domain and file is None and url is None:
            file = f'result/{date}/{domain}.subdomains.with.http.txt'
            output_filename = f'{domain.replace(".", "-")}-{sys._getframe().f_code.co_name}'
        elif file and domain is None and url is None:
            # 如果从文件输入则结果以时间为文件名
            output_filename = date
        elif url and domain is None and file is None:
            # domain = date
            output_filename = date
            file = f"temp.{sys._getframe().f_code.co_name}.txt"
            with open(urlsfile, "w", encoding="utf-8") as f:
                f.write(url)
        else:
            logger.error(f'[-] 请检查输入的文件 or domain 是否正确')
            return
        # cmd = f'{pwd}/Ehole/ehole{suffix} finger  -l result/{date}/{domain}.subdomains_with_http.txt -o result/{date}/ehole_log/{domain.replace(".", "-")}-ehole.xlsx'
        cmd = f'{pwd}/Ehole/ehole{suffix} finger  -l {file} -o {output_folder}/{output_filename}.xlsx'
        logger.info(f"[+] command:{cmd}")
        os.system(cmd)
        logger.info(
            f"[+] Generate file: {output_folder}/{output_filename}.xlsx")
        # 最后移除临时文件
        if url and domain is None and file is None:
            if os.path.exists(file):
                os.remove(file)

    @logger.catch
    def webanalyze(url=url, file=urlsfile):
        '''
        webanalyze 0.3.7
        不输出文件，只在console 按所需格式打印
        # webanalyze.exe -apps technologies.json -host http://139.198.21.26/phpmyadmin/  -output csv -crawl 3
        # webanalyze.exe -crawl 3 -host testphp.vulnweb.com -output json >> 22.txt
        :return:
        '''
        logger.info(
            '-' * 10 + f'start {sys._getframe().f_code.co_name}' + '-' * 10)
        # 创建该工具的结果文件夹
        # output_folder = f"result/{date}/{sys._getframe().f_code.co_name}_log"
        output_folder = f'{finger_log_folder}/{sys._getframe().f_code.co_name}log'
        if os.path.exists(output_folder) is False:
            os.makedirs(output_folder)

        if domain and file is None and url is None:
            file = f'result/{date}/{domain}.subdomains.with.http.txt'
            output_filename = f'{domain}.{sys._getframe().f_code.co_name}'
        elif file and domain is None and url is None:
            # 如果从文件输入则结果以时间为文件名
            output_filename = date
            # domain = date
        elif url and domain is None and file is None:
            # domain = date
            output_filename = date
            file = f"temp.{sys._getframe().f_code.co_name}.txt"
            with open(urlsfile, "w", encoding="utf-8") as f:
                f.write(url)
        else:
            logger.error(f'[-] 请检查输入的文件 or domain 是否正确')
            return
        # o {output_folder}/{output_filename}.xlsx -output csv json
        # > {output_folder}/{output_filename}.csv'
        cmdstr = f'{pwd}/webanalyze/webanalyze{suffix} -apps {pwd}/webanalyze/technologies.json -hosts {file}  -crawl 5 -output csv'
        # cmdstr = f'{pwd}/webanalyze/webanalyze{suffix} -apps technologies.json -hosts {file}  -output csv -crawl 5'
        logger.info(f"[+] command:{cmdstr}")
        cmd = cmdstr.split(' ')
        result1 = __subprocess2(cmd)
        finger_list = []

        result_str = ''
        for i in range(7, len(result1)):
            result_str += result1[i].decode().strip()
        tmp = re.split('http[s]?://', result_str, flags=re.I)
        for i in tmp[1:]:
            tmp2 = re.split('\(.*?s\):', i, 1, re.I)
            finger_list.append(tmp2)
            print(tmp2)
        with open(f'{output_folder}/{output_filename}.csv', 'w', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerows(finger_list)
        logger.info(
            f"[+] Generate file: {output_folder}/{output_filename}.csv")

        if url and domain is None and file is None:
            if os.path.exists(file):
                os.remove(file)

    httpx(url=url, file=urlsfile)
    ehole(url=url, file=urlsfile)
    webanalyze(url=url, file=urlsfile)


@logger.catch
def run(url=None, urlfile=None, date=None):
    '''
    usage:

        python main.py --url xxx.com
        python main.py --urlfile urls.txt

    :param str  url:     One url
    :param str  urlfile:    File path of urlsfile per line
    :return:
    '''
    create_logfile()
    import datetime
    date1 = str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
    date = date if date else date1
    if url and urlfile is None:
        manager(domain=None, url=url, urlsfile=None, date=date)
    elif urlfile and url is None:
        if os.path.exists(urlfile):
            manager(domain=None, url=None, urlsfile=urlfile, date=date)
        else:
            logger.error(f'{urlfile} not found!')
    else:
        logger.error(
            "Please check --url or --urlfile\nCheck that the parameters are correct.")


if __name__ == '__main__':
    fire.Fire(run)