import inspect
import os
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


def __subprocess1(cmd=None, timeout=None, path=None):
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
def __subprocess2(cmd):
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
