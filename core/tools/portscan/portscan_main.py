import csv
import hashlib
import inspect
import json
import os
import shutil
import subprocess
import sys
import dns
import fire
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
        print("get system type error")
        exit(1)


# 进度记录,基于json
def progress_record_old(date=None, target=None, module=None, value=None, finished=False):
    logfile = f"result/{date}/log.json"
    if os.path.exists(logfile) is False:
        shutil.copy("config/log_template.json", f"result/{date}/log.json")
    with open(logfile, "r", encoding="utf-8") as f1:
        log_json = json.loads(f1.read())
    if finished is False:
        # 读取log.json 如果是false则扫描，是true则跳过
        if log_json[module] is False:
            return False
        elif log_json[module] is True:  # 即log_json[module] 为true的情况
            return True
    elif finished is True:
        log_json[module] = True
        with open(logfile, "w", encoding="utf-8") as f:
            f.write(json.dumps(log_json))
        return True


# 进度记录,基于json
def progress_record(date=None, target=None, module="portscan", value=None, finished=False):
    target_log = {"domain": False,
                  "emailcollect": False,
                  "survivaldetect": False,
                  "finger": False,
                  "portscan": False,
                  "sensitiveinfo": {
                      "scanned_targets": []
                  },
                  "vulscan": {
                      "webattack": False,
                      "hostattack": False
                  }
                  }
    logfile = f"result/{date}/log.json"
    if os.path.exists(logfile) is False:
        shutil.copy("config/log_template.json", f"result/{date}/log.json")
    with open(logfile, "r", encoding="utf-8") as f1:
        log_json = json.loads(f1.read())
    if finished is False:
        # 读取log.json 如果是false则扫描，是true则跳过
        if target not in dict(log_json["target_log"]).keys():
            log_json["target_log"][target] = target_log
            with open(logfile, "w", encoding="utf-8") as f:
                f.write(json.dumps(log_json))
            return False
        else:
            if log_json["target_log"][target][module] is False:
                return False
            # elif log_json["target_log"][target][module] is True:  # 即log_json["target_log"][target][module] 为true的情况
            else:
                return True
    elif finished is True:
        # 如果已经存在对应目标的target_log 字典,则直接修改即可，否则添加target_log 并将domain键值设为true
        # if target not in dict(log_json["target_log"]).keys():
        if target in dict(log_json["target_log"]).keys():
            log_json["target_log"][target][module] = True
        else:
            target_log[module] = True
            log_json["target_log"][target] = target_log
        with open(logfile, "w", encoding="utf-8") as f:
            f.write(json.dumps(log_json))
        return True


# def manager(domain=None,ip=None,ips=None,ipfile=None,date="2022-09-02-00-01-39"):
@logger.catch
def manager(domain=None, ip=None, ipfile=None, date="2022-09-02-00-01-39"):
    logger.info('\n' + '<' * 18 + f'start {__file__}' + '>' * 18)
    suffix = get_system()
    root = os.getcwd()
    pwd_and_file = os.path.abspath(__file__)
    pwd = os.path.dirname(pwd_and_file)  # E:\ccode\python\006_lunzi\core\tools\domain

    # 获取当前目录的前三级目录，即到domain目录下，来寻找exe domain目录下
    grader_father = os.path.abspath(os.path.dirname(pwd_and_file) + os.path.sep + "../..")
    # print(grader_father) # E:\ccode\python\006_lunzi\core
    # 创建存储工具扫描结果的文件夹
    portscan_log_folder = f"result/{date}/portscan_log"
    if os.path.exists(portscan_log_folder) is False:
        os.makedirs(portscan_log_folder)

    # 三种模式
    if domain and ip is None and ipfile is None:
        # ipfile = f'result/{date}/{domain}.subdomains.ips.txt'
        #ipfile = f"result/{date}/{domain}.nocdn.ips.txt"
        ipfile = f"result/{date}/{domain}.final.subdomains.txt"
        output_filename_prefix = domain
    elif ipfile and domain is None and ip is None:
        ipfile = ipfile
        output_filename_prefix = date
    elif ip and domain is None and ipfile is None:
        output_filename_prefix = ip
        ipfile = f"temp.ips.txt"
        with open(ipfile, "w", encoding="utf-8") as f:
            f.write(ip)
    else:
        logger.error("[-] Please --domain or --ip or --ipfile")
        exit(1)

    # naabu 可以对域名反查ip然后端口扫描，也可以对ips进行端口扫描
    # 目前实现对ipfile和子域名的扫描
    @logger.catch
    def naabu(ip=ip, ipfile=ipfile):
        '''
        naabu 2.1.1
        :return:
        windows下  naabu 不能进行主机存活扫描 不支持-sn参数，所以不能用naabu进行c段扫描，每个ip都扫描1000个端口太浪费时间了
        '''
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)
        ports_str = "22,80,1433,1521,3389,8009,8080,8443"
        ports_str = "21,22,23,25,53,53,69,80,81,88,110,111,111,123,123,135,137,139,161,177,389,427,443,445,465,500,515," \
                    "520,523,548,623,626,636,873,902,1080,1099,1433,1434,1521,1604,1645,1701,1883,1900,2049,2181,2375," \
                    "2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379," \
                    "7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,11211,27017,33848," \
                    "37777,50000,50070,61616"
        # NmapTop100 = "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"
        # NmapTop1000 = "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"

        # print(domain,ip,ips,ipfile)
        # toolname =
        output_filename = f'{portscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}'
        # -exclude-cdn, -ec	  skip full port scans for CDN's (only checks for 80,443)
        # -proxy string		 socks5 proxy (ip[:port] / fqdn[:port]
        # -proxy-auth string		socks5 proxy authentication (username:password)
        cmdstr = f'{pwd}/naabu/naabu{suffix} -source-ip 8.8.8.8:22 -rate 1000 -top-ports 1000 -silent -no-color -list {ipfile} -csv -o {output_filename}.csv'
        # naabu -list hosts.txt -p - 扫描全部  -exclude-cdn 跳过cdn检测，cdn只检查80 443
        # cmd = pwd + f'/naabu{suffix} -p "{ports_str}" -silent -no-color -scan-all-ips -list result/{date}/{domain}.final.subdomains.txt -o {portscan_log_folder}/{domain}.{sys._getframe().f_code.co_name}.txt'
        # nmap 常见100个端口 -scan-all-ips
        # cmdstr = f'{pwd}/naabu{suffix} -top-ports 100 -silent -no-color -list result/{date}/{domain}.final.subdomains.txt -o {portscan_log_folder}/{domain}.{sys._getframe().f_code.co_name}.txt'
        logger.info(f"[+] command:{cmdstr}")
        os.system(cmdstr)
        logger.info(f'[+] {sys._getframe().f_code.co_name} finished,outputfile:{output_filename}.csv')
        with open(f"{output_filename}.csv", "r") as f1:
            reader = csv.reader(f1)
            head = next(reader)
            with open(f"result/{date}/{output_filename_prefix}.ports.txt", "w") as f2:
                for row in reader:
                    # baidu.com:8080  192.168.1.1:53
                    lline = f"{row[0]}:{row[2]}" if row[0] else f"{row[1]}:{row[2]}"
                    f2.write(lline + '\n')
        logger.info(f'[+] [+] IP and port outputfile: result/{date}/{output_filename_prefix}.ports.txt')

    @logger.catch
    def TxPortMap(ip=ip, ipfile=ipfile):
        '''
        TxPortMap 20211210
        :return:
        '''
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)
        ports_str = "22,80,1433,1521,3389,8009,8080,8443"
        ports_str = "21,22,23,25,53,53,69,80,81,88,110,111,111,123,123,135,137,139,161,177,389,427,443,445,465,500,515," \
                    "520,523,548,623,626,636,873,902,1080,1099,1433,1434,1521,1604,1645,1701,1883,1900,2049,2181,2375," \
                    "2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379," \
                    "7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,11211,27017,33848," \
                    "37777,50000,50070,61616"
        outputfile = f'{portscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.txt'
        # cmdstr = f'{pwd}/TxPortMap/TxPortMap{suffix} -p {ports_str} -nbtscan -l {ipfile} -o {outputfile}'
        cmdstr = f'{pwd}/TxPortMap/TxPortMap{suffix} -t1000 -nbtscan -ep 25,110 -l {ipfile} -o {outputfile}'
        logger.info(f"[+] command:{cmdstr}")
        os.system(cmdstr)
        logger.info(f'[+] {sys._getframe().f_code.co_name} finished,outputfile:{outputfile}')
        # with open(f"{outputfile}", "r") as f1:
        #     with open(f"result/{date}/{output_filename_prefix}.ports.txt", "w") as f2:
        #         for lline in f1.read():
        #             lline = lline.strip().split()[0]
        #             f2.write(lline + '\n')
        # logger.info(f'[+] [+] IP and port outputfile: result/{date}/{output_filename_prefix}.ports.txt')

    # win不可用先剔除
    @logger.catch
    def dismap(ip=ip, ipfile=ipfile):
        '''
        dismap 0.4
        :return:
        '''
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)
        ports_str = "22,80,1433,1521,3389,8009,8080,8443"
        ports_str = "21,22,23,25,53,53,69,80,81,88,110,111,111,123,123,135,137,139,161,177,389,427,443,445,465,500,515," \
                    "520,523,548,623,626,636,873,902,1080,1099,1433,1434,1521,1604,1645,1701,1883,1900,2049,2181,2375," \
                    "2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379," \
                    "7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,11211,27017,33848," \
                    "37777,50000,50070,61616"
        # print(domain,ip,ips,ipfile)
        outputfile = f'{portscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.txt'
        cmdstr = f'{pwd}/dismap/dismap{suffix} --file {ipfile} --np -p {ports_str} -o {outputfile}'
        logger.info(f"[+] command:{cmdstr}")
        os.system(cmdstr)
        logger.info(f'[+] {sys._getframe().f_code.co_name} finished,outputfile:{outputfile}')

    # 写好了，暂不调用了，这个项目使用了nmap的库，并对端口进行指纹识别，同时也借用了naabu的思路，但是是2020年的，同时使用的是connect连接，不是syn
    @logger.catch
    def nmaps(ip=ip, ipfile=ipfile):
        '''
        nmaps 1.0 2020
        :return:
        '''
        logger.info('<' * 10 + f'start {sys._getframe().f_code.co_name}' + '>' * 10)
        ports_str = "22,80,1433,1521,3389,8009,8080,8443"
        ports_str = "21,22,23,25,53,53,69,80,81,88,110,111,111,123,123,135,137,139,161,177,389,427,443,445,465,500,515," \
                    "520,523,548,623,626,636,873,902,1080,1099,1433,1434,1521,1604,1645,1701,1883,1900,2049,2181,2375," \
                    "2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379," \
                    "7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,11211,27017,33848," \
                    "37777,50000,50070,61616"
        # print(domain,ip,ips,ipfile)-host 44.228.249.3 -top-ports -nC -source-ip 8.8.8.8 -o 22.txt
        # -iL 1.txt -top-ports -nC -source-ip 8.8.8.8 -o 22.txt -silent -retries 2
        outputfile = f'{portscan_log_folder}/{output_filename_prefix}.{sys._getframe().f_code.co_name}.txt'
        cmdstr = f'{pwd}/nmaps/nmaps{suffix} -top-ports 100 -silent -source-ip 8.8.8.8 -retries 2 -nC -iL {ipfile} -o {outputfile}'
        logger.info(f"[+] command:{cmdstr}")
        os.system(cmdstr)
        logger.info(f'[+] {sys._getframe().f_code.co_name} finished,outputfile:{outputfile}')

    def run():
        target = domain if domain else hashlib.md5(bytes(date, encoding='utf-8')).hexdigest()
        if progress_record(date=date, target=target, module="portscan", finished=False) is False:
            naabu(ip=None, ipfile=ipfile)
            TxPortMap(ip=None, ipfile=ipfile)
            # nmaps(ip=None,ipfile=ipfile)
            # dismap(ip=None,ipfile=ipfile)
            progress_record(date=date, target=target, module="portscan", finished=True)

    run()


@logger.catch
def run(ip=None, ips=None, ipfile=None, date=None):
    '''
    usage:

        python main.py --ip 127.0.0.1
        python main.py --ips ips.txt

    :param str  url:     One ip
    :param str  urlfile:    File path of ipfile per line
    :return:
    '''
    # 后面吧ip 支持cidr,去掉ips参数
    create_logfile()
    import datetime
    date1 = str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
    date = date if date else date1
    if ip and ipfile is None:
        manager(domain=None, ip=ip, ipfile=None, date=date)
    elif ipfile and ip is None:
        if os.path.exists(ips):
            manager(domain=None, ip=None, ipfile=ipfile, date=date)
        else:
            logger.error(f'{ips} not found!')
    else:
        logger.error("Please check --ip or --ips\nCheck that the parameters are correct.")


if __name__ == '__main__':
    fire.Fire(run)
    # http://testphp.vulnweb.com/vendor
    # manager(domain="vulnweb.com",ip=None,ips=None,date="2022-09-02-00-01-39")
    # manager(domain="tiqianle.com", ip=None, date="2022-09-02-00-01-39")
