
# !/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
------------------------------------------------------------------------------
	CTFR - 04.03.18.02.10.00 - Sheila A. Berta (UnaPibaGeek)
------------------------------------------------------------------------------
"""

## # LIBRARIES # ##
import re

import fire
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
## # CONTEXT VARIABLES # ##
version = 1.2


## # MAIN FUNCTIONS # ##


# def banner():
#     global version
#     b = '''
#           ____ _____ _____ ____
#          / ___|_   _|  ___|  _ \
#         | |     | | | |_  | |_) |
#         | |___  | | |  _| |  _ <
#          \____| |_| |_|   |_| \_\\
#
#      Version {v} - Hey don't miss AXFR!
#     Made by Sheila A. Berta (UnaPibaGeek)
# 	'''.format(v=version)
#     print(b)


# def clear_url(target):
#     return re.sub('.*www\.', '', target, 1).split('/')[0].strip()
# def parse_args():
#     import argparse
#     parser = argparse.ArgumentParser()
#     parser.add_argument('-d', '--domain', type=str, required=True, help="Target domain.")
#     parser.add_argument('-o', '--output', type=str, help="Output file.")
#     return parser.parse_args()



def save_subdomains(subdomain, output_file):
    with open(output_file, "a", encoding="utf-8") as f:
        f.write(subdomain + '\n')
        f.close()


def get_ctfr1(domain,output=None):
    sub_domains_list=[]
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    res = requests.get(url=url,verify=False).json()
    for i in list(res):
        sub_domains_list.extend([d.replace("*.","") for d in i["dns_names"]])
    # print(list(set(sub_domains_list)))
    return list(set(sub_domains_list))




def get_ctfr2(domain,output=None):
    # banner()
    # args = parse_args()
    subdomains_list = []
    # target = clear_url(args.domain)
    # output = args.output
    req = requests.get("https://crt.sh/?q=%.{d}&output=json".format(d=domain))
    if req.status_code != 200:
        print("[X] Information not available!")
        exit(1)
    for (key, value) in enumerate(req.json()):
        subdomains_list.extend([i.replace("*.","") for i in value['name_value'].split("\n")])
    subdomains_list = list(set(subdomains_list))
    # print(subdomains_list)
    return subdomains_list


def ctfr(domain,output=None):
    subdomains_list = []
    subdomains_list.extend(get_ctfr1(domain))
    subdomains_list.extend(get_ctfr2(domain))
    subdomains_list = list(set(subdomains_list))
    # print(subdomains_list)
    with open(output,'w',encoding='utf-8') as f:
        for subdomain in subdomains_list:
            f.write(subdomain+'\n')
    print(f'[+] ctfr outputfile:{output}')
    return subdomains_list



if __name__ == '__main__':
    fire.Fire(ctfr)
    # subdomains_list=ctfr("duxiaoman.com")
    # print(subdomains_list)
    # ctfr()



