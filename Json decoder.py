import os, shutil
import json
import jsonpath

#filename=input("输入文件位置\n")
#file=open(filename,'rb',encoding='utf-8')
fr=open('Edge_20190517.json',encoding='utf-8')
data=json.load(fr)
#print(data)
#js=json.dumps(json.load(data))

dic_begin={}
dic_end={}
for v in data: #遍历数据报
    #print(v)
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
    if HASH in dic_begin:
        dic_end[HASH]=time
    else:
        dic_end[HASH]=time
        dic_begin[HASH]=time

fw=open('result.txt','w+',encoding='utf-8')
for key in dic_begin.keys():
    print('key：'+key+' '+'begin:'+dic_begin[key]+' '+'end:'+dic_end[key]+"\n")
    fw.write('key：'+key+' '+'begin:'+dic_begin[key]+' '+'end:'+dic_end[key]+"\n")
fw.close()