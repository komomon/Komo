"""

"""
#core.tools.domain.OneForAll.
from common import utils
from common.module import Module
import os,json

'''
从其他工具的结果获取子域，result/temp/domain.many_tools_subdomain.txt，交给oneforall 去重，去判断是否有cdn，ip title banner等信息

'''
class CustomDomainTools(Module):
    def __init__(self, domain):
        Module.__init__(self)
        self.domain = domain
        self.module = 'other_tools'
        self.source = "other_tools"
    # other_tools 获得返回结果
    def do_brute(self):
        #self.subdomains = ['www.baidu.com','abcdef.baidu.com']
        subdomain_tmp = []
        other_tools_scan_result_file = "../../../../result/temp/" + self.domain+'.many.tools.subdomains.txt'
        if os.path.exists(other_tools_scan_result_file):
            # print(cunzai)
            with open(other_tools_scan_result_file,'r',encoding='utf-8') as f:
                for line in f.readlines():
                    if line.strip() !="":
                        subdomain_tmp.append(line.strip())
            self.subdomains.update(set(subdomain_tmp))
            # print(self.subdomains)
        else:
            print(other_tools_scan_result_file,' not exist!!!')
        # fd = open("result/temp/"+ self.domain+'.amass.json')
        # fd.close()
        # 移除临时文件
        #os.remove("result/temp/"+ self.domain+'.amass.json')

    def run(self):
        # 判断是否安装amass
        # if os.system('amass -version') == 0:
        self.begin()
        self.do_brute()
        self.finish()
        self.save_json()
        self.gen_result()
        self.save_db()


def run(domain):
    """
    类统一调用入口

    :param str domain: 域名
    """
    amass = CustomDomainTools(domain)
    amass.run()