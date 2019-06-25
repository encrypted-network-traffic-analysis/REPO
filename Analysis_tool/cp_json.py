
import scapy_http.http
import scapy.all as scapy
import scapy
import json
import jsonpath
import string as string
import csv
from collections import defaultdict

dic = defaultdict(list)
f_time=""
def cp():
    fr=open('test.json',encoding='utf-8')
    data=json.load(fr)
    for v in data:
        if 'ssl' in v['_source']['layers']:
            if 'ssl.record.length' in v['_source']['layers']['ssl']['ssl.record']:
                sizes=v['_source']['layers']['ssl']['ssl.record']['ssl.record.length']
            else:
                continue
        else:
            continue
        if 'ip.src' in v['_source']['layers']['ip']:
            ip_src=v['_source']['layers']['ip']['ip.src']
        if 'ip.dst' in v['_source']['layers']['ip']:
            ip_dst=v['_source']['layers']['ip']['ip.dst']
        if 'tcp' in v['_source']['layers']:
            tcp_srcport=v['_source']['layers']['tcp']['tcp.srcport']
        if 'icmp' in v['_source']['layers']:
            tcp_srcport=v['_source']['layers']['icmp']['tcp']['tcp.srcport']
        if 'tcp' in v['_source']['layers']:
            tcp_dstport=v['_source']['layers']['tcp']['tcp.dstport']
        if 'icmp' in v['_source']['layers']:
            tcp_dstport=v['_source']['layers']['icmp']['tcp']['tcp.dstport']
        if ip_src<=ip_dst:
            if tcp_dstport<=tcp_srcport:
                HASH=ip_src+' '+ip_dst+' '+tcp_dstport+' '+tcp_srcport
            if tcp_dstport>tcp_srcport:
                HASH=ip_src+' '+ip_dst+' '+tcp_srcport+' '+tcp_dstport
        elif ip_src>ip_dst:
            if tcp_dstport<=tcp_srcport:
                HASH=ip_dst+' '+ip_src+' '+tcp_dstport+' '+tcp_srcport
            if tcp_dstport>tcp_srcport:
                HASH=ip_dst+' '+ip_src+' '+tcp_srcport+' '+tcp_dstport
        time=v['_source']['layers']['frame']['frame.time_epoch']
        if HASH in dic:
            dic[HASH][1]=time
            dic[HASH][2]+=int(sizes)
            dic[HASH][3]+=1
        else:
            dic[HASH].append(time)
            dic[HASH].append(time)
            dic[HASH].append(int(sizes))
            dic[HASH].append(1)
    fw = open('result.txt', 'a+', encoding='utf-8')
    global csvF
    csvF = open('csvF.csv', 'a+', newline="")
    csvwriter = csv.writer(csvF)
    for key in dic.keys():
        csvwriter.writerow([key, dic[key][0], dic[key][1], dic[key][2],dic[key][3]])
        print('key：'+str(key)+' '+'begin:' +
          str(dic[key][0])+' '+'end:'+str(dic[key][1])+' '+'len:'+str(dic[key][2])+' count:'+str(dic[key][3])+"\n")
        fw.write('key：'+str(key)+' '+'begin:' +
             str(dic[key][0])+' '+'end:'+str(dic[key][1])+' '+'len:'+str(dic[key][2])+' count:'+str(dic[key][3])+"\n")
    fw.close()
    csvF.close()
    dic.clear()


if __name__ == "__main__":
    csvF = open('csvF.csv', 'w+', newline="")
    csvwriter = csv.writer(csvF)
    csvwriter.writerow(['key', 'begin', 'end', 'size', 'packages'])
    csvF.close()
    cp()
