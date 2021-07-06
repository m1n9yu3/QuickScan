# coding = utf-8
import time

import requests
import socket
import ipaddress
import argparse
import json
import re
from concurrent.futures import ThreadPoolExecutor
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

arg = argparse.ArgumentParser(description="一个快速扫描内网 资产的自动化脚本. ")
arg.add_argument('ip', type=str, help='ip地址/子网掩码位数, 样例: 10.0.0.0/8')

socket.setdefaulttimeout(0.2)

config_dict_data = {}


def init_config(config="data.txt"):
    global config_dict_data
    with open(file=config, mode='r', encoding="utf-8") as f:
        config_dict_data = dict(json.load(fp=f))


def http_scan(ip):
    headers = {
        "User-Agent": "Chrome (AppleWebKit/537.1; Chrome50.0; Windows NT 6.3; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E)"}
    try:
        ip = str(ip)
        url = 'http://%s' % ip
        response = requests.get(url=url, headers=headers, verify=False, timeout=2)
        content = response.content.decode('utf-8')

        re_list = [
            "top.location.href='(.*?)';",
            'content="0; *URL=(.*?)"'
        ]

        for i in re_list:
            res = re.findall(i, content)
            if res:
                url = url + res[0].replace("'", "")
                response = requests.get(url=url, headers=headers, verify=False, timeout=2)
                content = response.content.decode('utf-8')
                # print(content)
                break

        keylist = list(config_dict_data.keys())
        for i in keylist:
            res = re.search(i, content)
            if res != None:
                print("%s, 是: %s" % (ip, config_dict_data[i]))
                break
        else:
            # print("\nip:%s\n%s" % (response.url, response.content.decode("utf-8")))
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


def get_ip(ip):
    res = ip.split("/")
    if len(res) == 2:
        ip_addr = ip.split("/")[0]
        netmask = ip.split("/")[1]
    elif len(res) == 1:
        ip_addr = ip.split("/")[0]
        netmask = 24
    elif len(res) == 0:
        ip_addr = res
        if re.findall("((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}", ip_addr) == []:
            raise Exception("ip 地址输入错误!!!")
        else:
            netmask = 24
    else:
        raise Exception("ip 地址输入错误!!!")

    # 对 ip 地址 进行分割
    cur_ip = ip_addr.split(".")
    if netmask == 8:
        cur_ip[1] = '0'
        cur_ip[2] = '0'
        cur_ip[3] = '0'
    elif netmask == 16:
        cur_ip[2] = '0'
        cur_ip[3] = '0'
    elif netmask == 24:
        cur_ip[3] = '0'
    else:
        # 这里 需要 进行子网划分，我就不划分了, 使用者自己听天由命吧
        pass

    ip_addr = '.'.join(cur_ip)
    try:
        print(ip_addr, netmask)
        net = ipaddress.ip_network(ip_addr + '/' + str(netmask))
    except:
        raise Exception("当前地址不正确!, 请检查当前的 ip 地址是否 符合 ipv4 特征， 如果符合，请提交issue. ")
    return net.hosts()


def main(ipaddr):
    init_config()
    ip = get_ip(ipaddr)

    print("-----------------内网扫描开始---------------%s-----" % ipaddr)
    print("-- 80端口开放的主机:")

    with ThreadPoolExecutor(max_workers=50) as T:
        Threads = [T.submit(port_scan, cur_ip, 80) for cur_ip in ip]
        [i.done() for i in Threads]
        res_list = [res.result() for res in Threads if res.result() is not None]

    print("-------------------- 内网扫描结果 ----------%s -----" % ipaddr)
    with ThreadPoolExecutor(max_workers=20) as T:
        Threads = [T.submit(http_scan, ip) for ip in res_list]
        [i.done() for i in Threads]


if __name__ == '__main__':
    args = arg.parse_args()
    ip = args.ip
    # print(ip)
    main(ip)
