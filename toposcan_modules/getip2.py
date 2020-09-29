# 导入所需要的包
# 导入scapy的所有功能，主要用于
from scapy.all import Ether,ARP,srp
# from scapy.all import show_interfaces
from pymysql import *
import re
from pyportscanner import pyscanner

# 首先要选择网卡的接口，就需要查看网卡接口有什么,在进行选择
# print(show_interfaces())
wifi = 'Intel(R) Wireless-AC 9462'

# 模拟发包,向整个网络发包，如果有回应，则表示活跃的主机
p = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst='192.168.8.102/24')
# ans表示收到的包的回复
ans, unans = srp(p, iface=wifi, timeout=5)

print("一共扫描到%d台主机：" % len(ans))

# 将需要的IP地址和Mac地址存放在result列表中
result = []
for s, r in ans:
    # 解析收到的包，提取出需要的IP地址和MAC地址
    result.append([r[ARP].psrc, r[ARP].hwsrc])
# 将获取的信息进行排序，看起来更整齐一点
result.sort()
# print(result)
# 打印出局域网中的主机
for ip, mac in result:
    print(ip, '------>mac地址 ：', mac)
# 写入文件
with open("result.txt", 'w') as f:
    for i in range(len(result)):
        # print(i)
        # print(result[i])
        result[i] = ': ' .join(result[i])
        f.write(result[i])
        f.write('\n')
# 至此已经获取到result.text文件

# 通过result.text文件获取mac目标，从而匹配出对应主机类型
with open('result.txt', 'r') as f:
    s = f.read()
    mac_aim = str(s.split())
    result = re.findall('(?:[a-fA-F\d]{2}(?:-|:)){5}[a-fA-F\d]{2}', mac_aim)
a = []
for i in result:
    a.append(i.replace("-",":")[:8])
result_search = ",".join(a)
result_search1 = result_search.upper()
result_search2 = result_search1.split(',')

def get_keys(d, value):
    return [k for k,v in d.items() if v == value]

def type_scan():
    conn = connect(host='192.168.8.16',port=33306,database='network',user='logaudit',password='xywa123$%^',charset='utf8')
    cs1 = conn.cursor() # 使用该连接并返回游标
    args = result_search2
    # print('args :',args)
    var_num = len(args)
    string = ', '.join(['"%s"' % args[i] for i in range(var_num)])
    sql = 'SELECT mac_perfix,spplier_desc FROM mac_spplier WHERE mac_perfix in ({})'.format(string)
    # pymysql 会验证非法字符， 遇到特殊字符先使用 escape_string 转换一下， 然后就可以正常插入了。
    cs1.execute(sql) # 执行一个数据库查询命令
    datalist = []
    alldata = cs1.fetchall() # 获取结果集中剩下的所有行
    # print('alldata:',alldata)
    alldata_new = dict(alldata)
    # print(alldata_new)
    data_key = alldata_new.keys()
    for s in args:
        if s in data_key:
            datalist.append(alldata_new[s])
        else:
            datalist.append("--")
    with open('middle.txt', 'w') as a:
        for datalist in datalist:
            a.write(datalist)
            a.write('\n')
    conn.close()
# 至此，已经捕获到了所有对应的主机类型

def server_scan():
    with open('port.txt', 'r') as f:
        port_server_target=[]
        for line in f:
            i = line.index('[')
            j = line.index(']')
            target = line[i+1:j]
            if target == '':
                port_server_target.append('没有端口信息')
            else:
                port_target = target.split(',')

                conn = connect(host='192.168.8.16',port=33306,database='network',user='logaudit',password='xywa123$%^',charset='utf8')
                cs1 = conn.cursor() # 使用该连接并返回游标
                args = port_target
                var_num = len(args)
                string = ', '.join(['"%s"' % args[i] for i in range(var_num)])
                sql = 'SELECT port_num,pro_name FROM event_level_policy WHERE port_num in ({})'.format(string)
                # pymysql 会验证非法字符， 遇到特殊字符先使用 escape_string 转换一下， 然后就可以正常插入了。
                cs1.execute(sql) # 执行一个数据库查询命令
                alldata = cs1.fetchall() # 获取结果集中剩下的所有行
                alldata_new = dict(alldata)
                data_key = list(alldata_new.keys())
                args_new = []
                for s in args:
                    s = eval(s)
                    args_new.append(s)
                port_server = []

                for s in args_new:
                    if s in data_key:
                        port_server.append(str(alldata_new[s]))
                    else:
                        port_server.append('___')
                dictlist_ps = dict(zip(args,port_server))
                port_server_target.append(dictlist_ps)
        with open("the_last_result.txt", 'w') as last_f:
            for i in range(len(f_1_ip)):
                last_f.write(f_1_ip[i])
                last_f.write('  ')
                last_f.write(f_1_mac[i])
                last_f.write('  :    ')
                last_f.write(f_2_cs[i])
                last_f.write(" ||------->>")
                last_f.write(str(port_server_target[i]))
                last_f.write('\n')

if __name__ == "__main__":
    type_scan()
    with open('result.txt', 'r') as f1, open('middle.txt', 'r') as f2:
        f_1, f_2 = f1.readlines(), f2.readlines()
        f_1_ip, f_1_mac, f_2_cs ,qwer= [], [], [], []
        for message in f_1:
            temp_ = message.split()
            f_1_ip.append(str(temp_[0]))
            f_1_mac.append(str(temp_[1]))
        scanner = pyscanner.PortScanner(target_ports=100, timeout=10, verbose=True)
        object = f_1_ip
        a = []
        for s in object:
            res = scanner.scan(s)
            a.append(res)
        for message in f_2:
            temp_ = message.split()
            f_2_cs.append(str(temp_[0]))
        str_a = ', '.join('%s' %id for id in a)
        with open("last-result.txt", 'w') as f:
            for i in range(len(f_1_ip)):
                f.write(f_1_ip[i])
                f.write('  ')
                f.write(f_1_mac[i])
                f.write('  :    ')
                f.write(f_2_cs[i])
                f.write("-------")
                f.write(str(a[i]))
                qwer.append(get_keys(a[i],'OPEN'))
                f.write('\n')
    with open('port.txt', 'w') as f:
        for i in range(len(qwer)):
            f.write(str(qwer[i]))
            f.write('\n')
    server_scan()
    print('探索完毕，请到——the_last_result.txt查看结果')