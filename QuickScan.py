# coding = utf-8

import requests
import socket
import threading
import ipaddress
import argparse
import json
import re
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

arg = argparse.ArgumentParser(description="一个快速扫描内网 资产的自动化脚本. ")
arg.add_argument('ip', type=str, help='ip地址/子网掩码位数, 样例: 10.0.0.0/8')

socket.setdefaulttimeout(0.001)
config = 'data.txt'

def scan(ip):
    headers = {
        "User-Agent": "Chrome (AppleWebKit/537.1; Chrome50.0; Windows NT 6.3; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E)"}
    try:
        ip = str(ip)
        url = 'http://%s' % ip
        # print(url)
        response = requests.get(url=url, headers=headers, verify=False, timeout=2)
        content = response.content.decode('utf-8')
        with open(file=config, mode='r', encoding="utf-8") as f:
            dictdata = dict(json.load(fp=f))
            keylist = list(dictdata.keys())
            for i in keylist:
                res = re.search(i, content)
                if res != None:
                    print("%s, 是: %s" % (ip, dictdata[i]))
                    break
            else:
                print("%s： 无法判断网页类型" % ip)
            # print(response.content.decode("utf-8"))
    except Exception as e:
        print(e)
        pass


def port_scan(ip, port):
    try:
        socket_new = socket.socket()

        addres = (str(ip), int(port))
        socket_new.connect(addres, )
        socket_new.close()
        print("  --: ", str(ip))
        return ip
    except Exception as e:
        # print(e)
        return None


class MyThread(threading.Thread):
    def __init__(self, func, args, name=''):
        threading.Thread.__init__(self)
        self.name = name
        self.func = func
        self.args = args
        self.result = self.func(*self.args)

    def get_result(self):
        try:
            return self.result
        except Exception:
            return None


def get_ip(ip):
    res = ip.split("/")
    if len(res) == 2:
        ip_addr = ip.split("/")[0]
        netmask = ip.split("/")[1]
    elif len(res) == 1:
        ip_addr = ip.split("/")[0]
        netmask = 24
    else:
        raise Exception("ip 地址输入错误!!!")

    net = ipaddress.ip_network(ip_addr + '/' + netmask)
    return net.hosts()


def main(ipaddr):
    threads = []
    ip = get_ip(ipaddr)

    print("-----------------内网扫描开始---------------%s-----" % ipaddr)
    print("-- 80端口开放的主机:")
    while True:
        try:
            cur_ip = next(ip)
            # print(cur_ip)
            cur_thread = MyThread(port_scan, (cur_ip, 80), port_scan.__name__)
            # cur_thread = threading.Thread(target=MyThread, args=(cur_ip, 80,), name=)
            threads.append(cur_thread)
            cur_thread.start()
        except:
            break

    for i in threads:
        i.join()

    res_list = []

    for i in threads:

        res = i.get_result()
        # print(res)
        if res != None:
            res_list.append(res)

    print("-------------------- 内网扫描结果 ----------%s -----" % ipaddr)

    for i in res_list:
        # print(i)
        MyThread(scan, (i,), scan.__name__).start()


if __name__ == '__main__':
    args = arg.parse_args()
    ip = args.ip
    # print(ip)
    main(ip)
    # scan('10.0.0.88')
