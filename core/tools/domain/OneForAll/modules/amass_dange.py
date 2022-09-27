"""
通过调用owasp amass 工具获得子域名列表结果
"""
#core.tools.domain.OneForAll.
from common import utils
from common.module import Module
import os,json


class OwaspAamss(Module):
    def __init__(self, domain):
        Module.__init__(self)
        self.domain = domain
        self.module = 'Amass'
        self.source = "Amass"
    # 调用amass 获得返回结果
    def do_brute(self):
        #self.subdomains = ['www.baidu.com','abcdef.baidu.com']

        import sys
        platform = sys.platform
        # 获取当前目录的前三级目录，即到domain目录下，来寻找exe
        grader_father = os.path.abspath(os.path.dirname(os.path.abspath(__file__)) + os.path.sep + "../..")

        if platform == 'win32':
            # os.system('.\\Plugins\\infoGather\\subdomain\\ksubdomain\\ksubdomain.exe -d {} -o {}'.format(domain, ksubdomain_file))
            cmd = grader_father+ '\\amass.exe enum enum -active -v -src  -d {} -json result/temp/{}.amass.json'.format(self.domain, self.domain)
            # os.system()
        elif "linux" in platform:
            cmd = grader_father + '\\amass enum enum -active -v -src  -d {} -json result/temp/{}.amass.json'.format(
                self.domain, self.domain)
            # os.system('chmod 777 ./Plugins/infoGather/subdomain/ksubdomain/ksubdomain_linux')
            # os.system('amass -d {} -o {}'.format(domain, ksubdomain_file))
        else:
            cmd = ""
            print("queshao amass")
            exit(1)



        # cmd = 'amass.exe enum -active -v -src  -d %s -json %s.amass.json ' % (self.domain, self.domain)
        os.system(cmd)
        amass = []
        fd = open("result/temp/"+ self.domain+'.amass.json')
        for line in fd:
            amass_data = json.loads(line.strip())
            if 'name' in amass_data:
                self.subdomains.update(amass_data['name'])
        fd.close()
        # 移除临时文件
        #os.remove("result/temp/"+ self.domain+'.amass.json')

    def run(self):
        # 判断是否安装amass
        if os.system('amass -version') == 0:
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
    amass = OwaspAamss(domain)
    amass.run()