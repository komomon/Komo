import os
import fire
import datetime
from loguru import logger
from core.tools.domain import domain_main
from core.tools.finger import finger_main

from core.tools.sensitiveinfo import sensitiveinfo_main
from core.tools.vulscan import vulscan_main
from core.tools.portscan import portscan_main
from core.download import download_tools

yellow = '\033[01;33m'
white = '\033[01;37m'
green = '\033[01;32m'
blue = '\033[01;34m'
red = '\033[1;31m'
end = '\033[0m'

version = 'v1.0'
message = white + '{' + red + version + ' #dev' + white + '}'

banner = f"""
{red}Komo is a comprehensive asset collection and vulnerability scanning tool{yellow}

██╗  ██╗ ██████╗ ███╗   ███╗ ██████╗ {message}{green}
██║ ██╔╝██╔═══██╗████╗ ████║██╔═══██╗
█████╔╝ ██║   ██║██╔████╔██║██║   ██║{blue}
██╔═██╗ ██║   ██║██║╚██╔╝██║██║   ██║
██║  ██╗╚██████╔╝██║ ╚═╝ ██║╚██████╔╝
╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝ {white} By Komomon
{end}                                  
"""


def create_logfile():
    if os.path.exists(f'{os.getcwd()}/log') is False:
        os.makedirs(f'{os.getcwd()}/log')
    logger.add(sink='log/runtime.log', level='INFO', encoding='utf-8')
    logger.add(sink='log/error.log', level='ERROR', encoding='utf-8')


class Komo(object):
    '''

    Komo help summary page

    Komo is an automated scanning tool set

    mode:
    install     Download the required tools
    all         all scan and attack
        --domain    one domain
        --domains   a domain file
    collect     run all collection modules :subdomain, finger, port, sensitive, poc, to_xray
        --domain    one domain
        --domains   a domain file
    subdomain   only collect subdomain
        --domain    one domain
        --domains   a domains file
    finger      only collect the survival URL and  fingerprint
        --url       one url
        --urls      an urls file
    portscan    only collect port from ip or ips
        --ip        one ip
        --ips       an ips file
    sensitive   only collect directory with crawl,email
        --url       one url
        --urls      an urls file
    webattack   only attack web from url or urls
        --url       one url
        --urls      an urls file
    hostattack  only attack ip from ip or ips
        --ip        one ip
        --ips       an ips file

    Example:
        python3 Komo.py install
        python3 Komo.py --domain example.com all
        python3 Komo.py --domains ./domains.txt all
        python3 Komo.py --domain example.com collect
        python3 Komo.py --domains ./domains.txt collect
        python3 Komo.py --domain example.com subdomain
        python3 Komo.py --domains ./domains.txt subdomain

        python3 Komo.py --url http://example.com finger
        python3 Komo.py --urls ./urls.txt finger
        python3 Komo.py --url http://example.com sensitive
        python3 Komo.py --urls ./urls.txt sensitive
        python3 Komo.py --url http://example.com webattack
        python3 Komo.py --urls ./urls.txt webattack

        python3 Komo.py --ip example.com portscan
        python3 Komo.py --ips ./domains.txt portscan
        python3 Komo.py --ip example.com hostattack
        python3 Komo.py --ips ./domains.txt hostattack


    :param domain:
    :param domains:
    :param url:
    :param urlsfile:
    :param ip:
    :param ips:
    :param attackflag:
    '''

    def __init__(self, domain=None, domains=None, url=None, urls=None, ip=None, ips=None, attackflag=False, date=None):

        date1 = str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
        self.domain = domain
        self.domains = domains  # domainsfile
        self.url = url
        self.urlsfile = urls
        self.ip = ip
        self.ips = ips
        self.attackflag = attackflag
        self.date = date if date else date1
        self.domains_list = []
        create_logfile()
        print(banner)

        if self.domain and self.domains is None:
            self.domains_list.append(self.domain)
        elif self.domains and self.domain is None:
            with open(self.domains, 'r', encoding='utf-8') as f:
                for line in f.readlines():
                    line = line.strip()
                    self.domains_list.append(line)
            self.domains_list = list(set(self.domains_list))

    def install(self):
        # download tools
        dd = download_tools.Download()
        dd.run()


    # 只进行子域扫描
    def subdomain(self):
        if self.domains_list:
            for domain in self.domains_list:
                domain_main.manager(domain=domain, date=self.date)
        else:
            logger.error("[-] Please check --domain or --domains")

    def finger(self):
        if self.url:
            finger_main.manager(domain=None, url=self.url, urlsfile=None, date=self.date)
        elif self.urlsfile:
            finger_main.manager(domain=None, url=None, urlsfile=self.urlsfile, date=self.date)
        else:
            logger.error("[-] Please check --url or --urlsfile")

    def portscan(self):
        if self.ip:
            portscan_main.manager(domain=None, ip=self.ip, ipfile=None, date=self.date)
        elif self.ips:
            portscan_main.manager(domain=None, ip=None, ipfile=self.ips, date=self.date)
        else:
            logger.error("[-] Please check --ip or --ips")

    # 敏感信息收集
    def sensitive(self):
        self.attackflag = False
        if self.url:
            sensitiveinfo_main.manager(domain=None, url=self.url, urlsfile=None, attackflag=self.attackflag,
                                       date=self.date)
        elif self.urlsfile:
            sensitiveinfo_main.manager(domain=None, url=None, urlsfile=self.urlsfile, attackflag=self.attackflag,
                                       date=self.date)
        else:
            logger.error("[-] Please check --url or --urlsfile")

    # 对urls进行漏洞扫描
    # def vulscan(self):
    def webattack(self):
        self.attackflag = True
        if self.url:
            sensitiveinfo_main.manager(domain=None, url=self.url, urlsfile=None, attackflag=self.attackflag,
                                       date=self.date)  # toxray
            vulscan_main.webmanager(domain=None, url=self.url, urlsfile=None, date=self.date)
        elif self.urlsfile:
            sensitiveinfo_main.manager(domain=None, url=None, urlsfile=self.urlsfile, attackflag=self.attackflag,
                                       date=self.date)
            vulscan_main.webmanager(domain=None, url=None, urlsfile=self.urlsfile, date=self.date)
        else:
            logger.error("[-] Please check --url or --urlsfile")

    # 对主机ip攻击
    def hostattack(self):
        self.attackflag = True
        if self.ip:
            vulscan_main.hostmanager(domain=None, ip=self.ip, ipfile=None, date=self.date)
            # sensitiveinfo_main.manager(domain=None, url=self.url, urlsfile=None, attackflag=self.attackflag,
            #                            date=self.date)
        elif self.ips:
            vulscan_main.hostmanager(domain=None, ip=None, ipfile=self.ips, date=self.date)
        else:
            logger.error("[-] Please check --ip or --ips")

    # 只扫描，不攻击 提供主域名或者主域名文件，顺序执行
    def collect(self):
        '''
        python main.py --domain tiqianle.com collect
        python main.py --domains file collect
        :return:
        '''
        self.attackflag = False
        if self.domains_list:
            for domain in self.domains_list:
                domain_main.manager(domain=domain, date=self.date)
            for domain in self.domains_list:
                finger_main.manager(domain=domain, url=None, urlsfile=None, date=self.date)
            for domain in self.domains_list:
                portscan_main.manager(domain=domain, ip=None, ipfile=None, date=self.date)
            for domain in self.domains_list:
                sensitiveinfo_main.manager(domain=domain, url=None, urlsfile=None, attackflag=self.attackflag,
                                           date=self.date)
                # vulscan_main.webmanager(domain=self.domain, url=None, urlsfile=None, date=self.date)
        else:
            logger.error("[-] Please check --domain or --domains")

    # 扫描+攻击 all_scan
    def all(self):
        '''
        python main.py --domain tiqianle.com all
        python main.py --domains tiqianle.com all
        :return:
        '''
        self.attackflag = True
        if self.domains_list:
            for domain in self.domains_list:
                domain_main.manager(domain=domain, date=self.date)
            for domain in self.domains_list:
                finger_main.manager(domain=domain, urlsfile=None, date=self.date)
            for domain in self.domains_list:
                portscan_main.manager(domain=domain, ip=None, ipfile=None, date=self.date)
            for domain in self.domains_list:
                sensitiveinfo_main.manager(domain=domain, url=None, urlsfile=None, attackflag=self.attackflag,
                                           date=self.date)
            for domain in self.domains_list:
                vulscan_main.webmanager(domain=domain, url=None, urlsfile=None, date=self.date)
            for domain in self.domains_list:
                vulscan_main.hostmanager(domain=domain, ip=None, ipfile=None, date=self.date)
        else:
            logger.error("[-] Please check --domain or --domains")


if __name__ == '__main__':
    fire.Fire(Komo)