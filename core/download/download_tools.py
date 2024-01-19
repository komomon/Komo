import os
import sys
from pprint import pprint
import shutil
import tarfile
import threading
import time
import traceback
import zipfile
import py7zr
from pathlib import Path
import platform

import tldextract
import yaml
import requests
from loguru import logger
from concurrent.futures import ThreadPoolExecutor, ALL_COMPLETED, wait, as_completed


def get_system():
    # global suffix
    platform = sys.platform
    if platform == 'win32':
        return "windows"
    elif "linux" in platform:
        return "linux"
    else:
        print("get system type error")
        exit(1)


def executor_callback(worker):
    logger.info("called worker callback function")
    worker_exception = worker.exception()
    result = worker.result()
    if worker_exception:
        print(worker_exception)
        # logger.exception("Worker return exception: {}".format(worker_exception))
    if result:
        print(result)


class Download:
    def __init__(self, proxy=None):
        # logger.info('检查是否已安装工具，如缺少将进行安装; tips: github网速可能不好，如下载频繁失败，建议百度云获取。')
        self.download_path = "download_tmp"
        self.proxy = proxy
        self.tools_dict = {}
        self.rootpath = os.getcwd()
        self.pwd = os.path.dirname(os.path.abspath(__file__))
        self.ostype = platform.system().lower()
        self.suffix = ".exe" if "windows" == self.ostype else ""
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.tools_installed = {}
        self.getconfig()
        if os.path.exists(self.download_path) is False:
            os.makedirs(self.download_path)
        for k in self.tools_dict.keys():
            if self.tools_dict[k]['whetherdownload'] is True:
                self.tools_installed[k] = False

    def getconfig(self):
        # ostype = platform.system().lower() #get_system()
        toolsyaml_path = f"{self.rootpath}/config/tools_{self.ostype}.yaml"
        # toolsyaml_path = "tools_windows.yaml"
        if os.path.exists(toolsyaml_path):
            with open(toolsyaml_path, 'r', encoding='utf-8') as f:
                msg = yaml.load(f, Loader=yaml.FullLoader)['download']
                classify = ['domain', 'emailcollect', 'survivaldetect', 'finger', 'portscan', 'sensitiveinfo',  'vulscan']
                # classify = ['sensitiveinfo']
                # xuanze_downloadtools = ['crawlergo']
                for i in classify:
                    self.tools_dict.update(msg[i])
                    # {'amass': {'link': 'https://github.com/OWASP/Amass/releases/download/v3.20.0/amass_windows_amd64.zip',
                    #            'toolname': 'amass',
                    #            'topath': ['core/tools/domain/amass/',
                    #                       'amass/'],
                    #            'whetherdownload': True}
            # pprint(self.tools_dict)
        else:
            logger.error(f"[-] not found {toolsyaml_path}")
            logger.error("Exit!")
            exit(1)

    # 解压到指定目录
    def unzipfile(self, filename, dirs="."):
        # if os.path.splitext(filename)[1] == ".zip":
        if os.path.exists(dirs) is False:
            os.makedirs(dirs)
        if zipfile.is_zipfile(filename):
            zf = zipfile.ZipFile(filename, 'r')
            zf.extractall(path=dirs)
            zf.close()
            logger.info(f"[+] unzip {filename} success.")
        elif tarfile.is_tarfile(filename):
            t = tarfile.open(filename)
            t.extractall(path=dirs)
            t.close()
            logger.info(f"[+] untar {filename} success.")
        # elif py7zr.is_7zfile(filename):
        #     with py7zr.SevenZipFile(filename, mode='r') as z:
        #         z.extractall(path=dirs)
        # 其他后缀的直接cp过去
        elif os.path.splitext(filename)[1] in ["", ".exe", ".db", ".7z"]:
            shutil.copy(filename, dirs)
        else:
            logger.error(f"[-] unzip {filename} to {dirs}failed.")
            return

    def downloadfile(self, url, dst_file, dst_path='download'):
        # dst_file = os.path.split(url)[1]
        target_filename = f'{dst_path}/{dst_file}'
        # if os.path.exists(dst_path) is False:
        #     os.makedirs(dst_path)
        if os.path.exists(target_filename) is False:
            try:
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"
                }
                proxies = {
                    'http': self.proxy,
                    'https': self.proxy
                }
                try:
                    domain_suffix = tldextract.extract(url)  # 通过域名后缀是否为空判断给的domain是domain 还是randomstr
                    # ExtractResult(subdomain='', domain='sdadadadawdawd', suffix='')
                    # print(domain_suffix)
                    if f"{domain_suffix.domain}.{domain_suffix.suffix}" in ["github.com"]:
                        status_code = requests.get("https://mirror.ghproxy.com/", headers=headers).status_code
                        if status_code == 200:
                            url = f"https://mirror.ghproxy.com/{url}"
                except Exception as e:
                    logger.exception(e)
                # print("url:",url)
                if self.proxy:# timeout=(3, 5) ,verify=False
                    response = requests.get(url, headers=headers, proxies=proxies, stream=True)
                else:
                    response = requests.get(url, headers=headers, stream=True)
                # print(url)
                # print(response.headers.get('content-length'))
                with open(target_filename, 'wb') as handle:
                # handle = open(target_filename, "wb")
                    for chunk in response.iter_content(chunk_size=1024):
                        if chunk:  # filter out keep-alive new chunks
                            handle.write(chunk)
                # handle.close()
                logger.info(f"[+] Download {dst_file} success.")
                # self.unzipfile(target_filename,dst_path)
                return target_filename
            except Exception as e:
                # print(e)
                logger.error(e)
                # logger.error(traceback.format_exc())
                logger.error(f"[-] Download {dst_file} fail!")
                return False
        else:
            logger.info(f"[*] {target_filename} already exists. Skip download.")
            return target_filename

    # def move(self,srcfile,dst_path):
    #     if os.path.exists(srcfile):
    #         if os.path.exists(dst_path):
    #             os.makedirs(dst_path)
    #         shutil.move(srcfile,dst_path)

    def handle(self, toolinfo):
        installflag = False
        try:
            if toolinfo['whetherdownload']:
                # 判断工具是否已经存在对应目录，不存在则下载,如果有则不再下载解压和重命名
                tool_filename = f"{toolinfo['topath'][0]}/{toolinfo['final_name']}"
                # dis whether exist
                if os.path.exists(tool_filename) is False:
                    installflag = True
                else:  # exists
                    # print("tool_filename:",tool_filename)
                    if os.path.isdir(tool_filename):
                        tool_filename = f"{toolinfo['topath'][0]}/{toolinfo['final_name']}/{toolinfo['tool_main_filename']}"
                        if os.path.exists(tool_filename) is False:
                            installflag = True
                            shutil.rmtree(f"{toolinfo['topath'][0]}/{toolinfo['final_name']}")  # 如果存在则删除文件夹,否则不能rename
                        else:
                            installflag = False
                    else:  # not dir
                        installflag = False
                # installflag is True-> install tools
                if installflag is True:
                    zip_path = self.downloadfile(url=toolinfo['link'], dst_file=toolinfo['downloadfile'],
                                                 dst_path=self.download_path)
                    time.sleep(2)
                    if zip_path:
                        # 检查最终目录是否存在最终的文件夹，如果有则不再解压和重命名
                        # if os.path.exists(f"{toolinfo['topath'][0]}/{toolinfo['final_name']}"):
                        self.unzipfile(filename=zip_path, dirs=toolinfo['topath'][0])
                        time.sleep(2)
                        if toolinfo['source_name'] != toolinfo['final_name']:
                            # shutil.move(f"{toolinfo['topath'][0]}/{toolinfo['source_name']}",f"{toolinfo['topath'][0]}/{toolinfo['final_name']}")
                            os.rename(f"{os.getcwd()}/{toolinfo['topath'][0]}/{toolinfo['source_name']}",
                                      f"{os.getcwd()}/{toolinfo['topath'][0]}/{toolinfo['final_name']}")
                            # os.remove(f"{toolinfo['topath'][0]}/{toolinfo['source_name']}")
                        self.tools_installed[toolinfo['toolname']] = True
                else:
                    self.tools_installed[toolinfo['toolname']] = True
                    logger.info(f"[*] {tool_filename} already exists. Skip download and unzip.")
                # 赋权
                if "linux" in sys.platform:
                    tool_filename = f"{toolinfo['topath'][0]}/{toolinfo['final_name']}"
                    if os.path.exists(tool_filename) is True:
                        if os.path.isdir(tool_filename):
                            tool_filename = f"{toolinfo['topath'][0]}/{toolinfo['final_name']}/{toolinfo['tool_main_filename']}"
                            if os.path.exists(tool_filename) is True:
                                os.system(f"chmod +x {tool_filename}")
                                logger.info(f"[+] chmod +x {tool_filename} success!")
                            else:
                                logger.error(f"[-] {tool_filename} non-existent, chmod +x {tool_filename} failed!")
                        else:  # not dir
                            os.system(f"chmod +x {tool_filename}")
                            logger.info(f"[+] chmod +x {tool_filename} success!")
                    else:
                        logger.error(f"[-] {tool_filename} non-existent, chmod +x {tool_filename} failed!")
        except KeyboardInterrupt:
            return False

    # 工具初始化
    def tools_init(self):
        if os.path.exists(f"core/tools/vulscan/vulmap/module/licenses"):
            if os.path.exists(f"core/tools/vulscan/vulmap/module/licenses/licenses.txt") is False:
                if os.path.exists("config/supplementary_files/vulmap/licenses.txt"):
                    shutil.copy("config/supplementary_files/vulmap/licenses.txt",
                                "core/tools/vulscan/vulmap/module/licenses")
                    logger.info(f"[+] {self.rootpath}/core/tools/vulscan/vulmap/vulmap.py initialization is complete")
                else:
                    logger.error(f"[-] config/supplementary_files/vulmap/licenses.txt not exist,initialization is failed")
        if os.path.exists(f"core/tools/vulscan/goon/conf.yml"):
            if os.path.exists(f"core/tools/vulscan/goon/goon{self.suffix}"):
                os.system(os.path.realpath(f"{self.rootpath}/core/tools/vulscan/goon/goon{self.suffix}"))
                logger.info(f"[+] {self.rootpath}/core/tools/vulscan/goon/goon{self.suffix} initialization is complete")
        if os.path.exists(f"core/tools/vulscan/afrog/afrog{self.suffix}"):
            os.system(f"{self.rootpath}/core/tools/vulscan/afrog/afrog{self.suffix}")
            logger.info(f"[+] {self.rootpath}/core/tools/vulscan/afrog/afrog{self.suffix} initialization is complete")

    # 可以捕获异常
    def run(self):
        flag = 0
        all_task = [self.executor.submit(self.handle, tinfo) for tinfo in self.tools_dict.values()]
        # done,notdone = wait(all_task, return_when=ALL_COMPLETED)
        for future in as_completed(all_task):
            try:
                result = future.result()
            except Exception as e:
                logger.exception(f"ThreadPoolExecutor:\n{e}")
                print(e)
                # logger.error(f"ThreadPoolExecutor:\n{e}")
            # else:
            #     print(result)
        # time.sleep(5)
        # 检查是否所有tools安装好了，否则退出
        for k, v in self.tools_installed.items():
            if v is False:
                logger.error(f"[-] {k} install failed")
                flag += 1
        if flag != 0:
            logger.error(f"[-] Please install tools that are not installed before using Komo")
            exit()
        else:
            logger.info(f"\n[+] All tools are installed\n")
        # 部分工具初始化
        self.tools_init()

    # 单线程版本
    def run1(self):
        flag = 0
        for toolinfo in self.tools_dict.values():
            self.handle(toolinfo=toolinfo)
        # time.sleep(5)
        # 检查是否所有tools安装好了，否则退出
        for k, v in self.tools_installed.items():
            if v is False:
                logger.error(f"[-] {k} install failed")
                flag += 1
        if flag != 0:
            logger.error(f"[-] Please install tools that are not installed before using Komo")
            exit()
        else:
            logger.info(f"\n[+] All tools are installed\n")
        # 部分工具初始化
        self.tools_init()

    # pass，找的c+c终止的方法，不太好用https://www.jianshu.com/p/45e526c792c3
    def run2(self):
        flag = 0
        all_task = [self.executor.submit(self.handle, tinfo) for tinfo in self.tools_dict.values()]
        try:
            while not list(reversed(all_task))[0].done():  # 判断最后一个任务是否取消/完成
                # 代替 wait(threadPool, return_when=FIRST_EXCEPTION)
                # 利用 while 堵塞且能够接收 KeyboardInterrupt 异常
                time.sleep(2)
        except KeyboardInterrupt:
            # 接收 KeyboardInterrupt 并取消剩余线程任务
            print('KeyboardInterrupt')
            for task in reversed(all_task):
                task.cancel()
        # time.sleep(5)
        # 检查是否所有tools安装好了，否则退出
        for k, v in self.tools_installed.items():
            if v is False:
                logger.error(f"[-] {k} install failed")
                flag += 1
        if flag != 0:
            logger.error(f"[-] Please install tools that are not installed before using Komo")
            exit()
        else:
            logger.info(f"\n[+] All tools are installed\n")

    def run3(self):
        flag = 0
        for tinfo in self.tools_dict.values():
            self.handle(tinfo)
        # all_task = [self.executor.submit(self.handle, tinfo) for tinfo in self.tools_dict.values()]
        # done,notdone = wait(all_task, return_when=ALL_COMPLETED)
        # time.sleep(5)
        # 检查是否所有tools安装好了，否则退出
        for k, v in self.tools_installed.items():
            if v is False:
                logger.error(f"[-] {k} install failed")
                flag += 1
        if flag != 0:
            logger.error(f"[-] Please install tools that are not installed before using Komo")
            exit()
        else:
            logger.info(f"\n[+] All tools are installed\n")


if __name__ == '__main__':
    dd = Download(proxy="http://127.0.0.1:7890")
    dd.run()
