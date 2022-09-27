import os
from pprint import pprint
import shutil
import tarfile
import threading
import time
import traceback
import zipfile
import py7zr
from pathlib import Path
import yaml
import requests
from loguru import logger
from concurrent.futures import ThreadPoolExecutor, ALL_COMPLETED, wait


class Download:
    def __init__(self):
        self.threads = []
        self.tools_dict = {}
        self.getconfig()
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.tools_installed = {}
        for k in self.tools_dict.keys():
            if self.tools_dict[k]['whetherdownload'] is True:
                self.tools_installed[k] = False

    def getconfig(self):
        filename = f"{os.path.dirname(os.path.abspath(__file__))}"
        toolsyaml_path = f"{os.getcwd()}/config/tools.yaml"
        toolsyaml_path = "tools.yaml"
        if os.path.exists(toolsyaml_path):
            with open(toolsyaml_path, 'r', encoding='utf-8') as f:
                msg = yaml.load(f, Loader=yaml.FullLoader)['download']
                classify = ['domain', 'finger', 'portscan', 'sensitiveinfo', 'vulscan']
                for i in classify:
                    self.tools_dict.update(msg[i])
        else:
            logger.error(f"[-] not found {toolsyaml_path}")
            logger.error("Exit!")

    def unzipfile(self,filename, dirs="."):
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
        elif os.path.splitext(filename)[1] in [".exe", ".db", ".7z"]:
            shutil.copy(filename, dirs)
        else:
            return

    def downloadfile(self,url,dst_file,dst_path='download'):
        target_filename = f'{dst_path}/{dst_file}'
        if os.path.exists(dst_path) is False:
            os.makedirs(dst_path)
        if os.path.exists(target_filename) is False:
            try:
                response = requests.get(url, stream=True)
                handle = open(target_filename, "wb")
                for chunk in response.iter_content(chunk_size=512):
                    if chunk:  # filter out keep-alive new chunks
                        handle.write(chunk)
                handle.close()
                logger.info(f"[+] Download {dst_file} success.")
                return target_filename
            except:
                # logger.error(traceback.format_exc())
                logger.error(f"[-] Download {dst_file} fail!")
                return False
        else:
            logger.info(f"[*] {target_filename} already exists. Skip download.")
            return target_filename

    def handle(self,toolinfo):
        if toolinfo['whetherdownload']:
            tool_filename = f"{toolinfo['topath'][0]}/{toolinfo['final_name']}"
            if os.path.exists(tool_filename) is False:
                zip_path = self.downloadfile(url=toolinfo['link'],dst_file=toolinfo['downloadfile'],dst_path='download_tmp')
                if zip_path:
                    self.unzipfile(filename=zip_path, dirs=toolinfo['topath'][0])
                    if toolinfo['source_name'] != toolinfo['final_name']:
                        # shutil.move(f"{toolinfo['topath'][0]}/{toolinfo['source_name']}",f"{toolinfo['topath'][0]}/{toolinfo['final_name']}")
                        os.rename(f"{toolinfo['topath'][0]}/{toolinfo['source_name']}",f"{toolinfo['topath'][0]}/{toolinfo['final_name']}")
                        # os.remove(f"{toolinfo['topath'][0]}/{toolinfo['source_name']}")
                    self.tools_installed[toolinfo['toolname']] = True
            else:
                self.tools_installed[toolinfo['toolname']] = True
                logger.info(f"[*] {tool_filename} already exists. Skip download.")

    def run(self):
        flag = 0
        all_task = [self.executor.submit(self.handle, (tinfo)) for tinfo in self.tools_dict.values()]
        wait(all_task, return_when=ALL_COMPLETED)
        for k,v in self.tools_installed.items():
            if v is False:
                logger.error(f"[-] {k} install failed")
                flag += 1
        if flag !=0:
            logger.error(f"[-] Please install tools that are not installed before using Komo")
            exit()
        else:
            logger.info(f"\n[+] All tools are installed\n")
        

if __name__ == '__main__':
    dd = Download()
    dd.run()