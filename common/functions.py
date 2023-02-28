import inspect
import json
import os
import shutil
import subprocess
import shlex
# 启用子进程执行外部shell命令
# @logger.catch
import sys
import tempfile
import traceback
from loguru import logger
import platform

OSTYPE = platform.system().lower()
SUFFIX = ".exe" if "windows" == OSTYPE else ""


def isexist(filepath):
    if os.path.exists(filepath):
        return True
    else:
        logger.error(f'{filepath} not found!')
        return False


def makedir0(path):
    if os.path.exists(path) is False:
        os.makedirs(path)
        logger.info(f'[+] Create {path} success.')


def __subprocess1111(cmd=None, timeout=None, path=None):
    '''
    rad 不支持结果输出到管道所以stdout=None才可以，即默认不设置
    :param cmd:
    :param timeout:
    :param path:
    :return:
    '''
    f_name = inspect.getframeinfo(inspect.currentframe().f_back)[2]  # 获取调用该函数的函数名称
    # cmd = shlex.split(cmd)
    # 执行外部shell命令， 输出结果存入临时文件中
    # logger.info(f"[+] command:{' '.join(cmd)}")
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
        # kill_process(f_name+get_system())
    except Exception as e:
        logger.error(traceback.format_exc())
        # logger.error(f'{sys._getframe().f_code.co_name} Reach Set Time and exit')
    finally:
        logger.info(f'{f_name} finished.')


# @logger.catch 基本不用，因为现在有了subprocess.run
def __subprocess2111(cmd):
    # if isinstance(cmd, str):
    #     cmd = cmd.split(' ')
    # elif isinstance(cmd, list):
    #     cmd = cmd
    # else:
    #     logger.error(f'[-] cmd type error,cmd should be a string or list: {cmd}')
    #     return
    out_temp = tempfile.SpooledTemporaryFile(max_size=10 * 1000, mode='w+b')
    lines = []
    try:
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


def progress_file_record(date=None, filename="domain", value=None):
    '''
    记录结果文件名称
    :param date:
    :param filename:
    :param value: 传输绝对路径
    :return:
    "file": {
    "many_tools_subdomain_file": {"filename": "","filesize": 0,"isexist": false},
    '''
    logfile = f"result/{date}/log.json"
    if os.path.exists(logfile) is False:
        shutil.copy("config/log_template.json", f"result/{date}/log.json")
    with open(logfile, 'r', encoding='utf-8') as f1:
        log_json = json.loads(f1.read())
        # log_dict = dict(log_json)
    if os.path.exists(value):
        log_json["file"][filename]["filename"] = value
        log_json["file"][filename]["filesize"] = os.path.getsize(value)
        log_json["file"][filename]["isexist"] = True
    with open(logfile, "w", encoding="utf-8") as f:
        f.write(json.dumps(log_json))
