
import scapy_http.http
import scapy.all as scapy
import scapy
import string as string
import csv
from collections import defaultdict

dic = defaultdict(list)
f_time=""
def cp(N):
    flag=True
    global dic
    while N > 0:
        dpkt = scapy.all.sniff(count=100)
        #pktdump = scapy.all.PcapWriter("demo.pcap", append=True, sync=True)
        # pktdump.write(dpkt)
        # pktdump.close()
        lenI = 0
        for data in dpkt:
            if flag:
                timeI = data.time
                time = str(timeI)
                f_time=time
                flag=False
            else:
                timeI = data.time-float(f_time)
                time = str(timeI)
            if not hasattr(data, 'len'):
                lenI = 0
            else:
                lenI += data.len
            len = str(lenI)
            if data.haslayer("IP"):
                ip_srcI = data["IP"].src
                ip_dstI = data["IP"].dst
                ip_dst = str(ip_dstI)
                ip_src = str(ip_srcI)
            #print('src_ip：'+ip_src+' dst_ip：'+ip_dst)
            if data.haslayer("TCP"):
                # 获取某一层的原始负载用.payload.original
                tcp_srcportI = data["TCP"].sport
                tcp_dstportI = data["TCP"].dport
                tcp_srcport = str(tcp_srcportI)
                tcp_dstport = str(tcp_dstportI)
            #print('src_port：'+str(tcp_srcport)+' dst_port：'+str(tcp_dstport))
            elif data.haslayer("UDP"):
                # 获取某一层的原始负载用.payload.original
                continue
                tcp_srcportI = data["UDP"].sport
                tcp_dstportI = data["UDP"].dport
                tcp_srcport = str(tcp_srcportI)
                tcp_dstport = str(tcp_dstportI)
            #print('src_port：'+str(tcp_srcport)+' dst_port：'+str(tcp_dstport))
            if data.haslayer("IP") and data.haslayer("TCP"):
             # or data.haslayer("UDP")):
                if data.haslayer("TCP"):
                    if ip_src <= ip_dst:
                        if tcp_dstport <= tcp_srcport:
                            HASH = ip_src+' '+ip_dst+' '+tcp_dstport+' '+tcp_srcport+' TCP'
                        if tcp_dstport > tcp_srcport:
                            HASH = ip_src+' '+ip_dst+' '+tcp_srcport+' '+tcp_dstport+' TCP'
                    elif ip_src > ip_dst:
                        if tcp_dstport <= tcp_srcport:
                            HASH = ip_dst+' '+ip_src+' '+tcp_dstport+' '+tcp_srcport+' TCP'
                        if tcp_dstport > tcp_srcport:
                            HASH = ip_dst+' '+ip_src+' '+tcp_srcport+' '+tcp_dstport+' TCP'
                elif data.haslayer("UDP"):
                    continue
                    if ip_src <= ip_dst:
                        if tcp_dstport <= tcp_srcport:
                            HASH = ip_src+' '+ip_dst+' '+tcp_dstport+' '+tcp_srcport+' UDP'
                        if tcp_dstport > tcp_srcport:
                            HASH = ip_src+' '+ip_dst+' '+tcp_srcport+' '+tcp_dstport+' UDP'
                    elif ip_src > ip_dst:
                        if tcp_dstport <= tcp_srcport:
                            HASH = ip_dst+' '+ip_src+' '+tcp_dstport+' '+tcp_srcport+' UDP'
                        if tcp_dstport > tcp_srcport:
                            HASH = ip_dst+' '+ip_src+' '+tcp_srcport+' '+tcp_dstport+' UDP'
                if HASH in dic:
                    dic[HASH][1] = time
                    dic[HASH][2] = str(int(dic[HASH][2])+lenI)
                    dic[HASH].append(len)
                else:
                    dic[HASH].append(time)
                    dic[HASH].append("timing...")
                    dic[HASH].append(len)
                    dic[HASH].append(len)
        fw = open('result.txt', 'a+', encoding='utf-8')
        #global csvF
        csvF = open('csvF.csv', 'a+', newline="")
        csvwriter = csv.writer(csvF)
        for key in dic.keys():
            csvwriter.writerow([key, dic[key][0], dic[key][1], dic[key][2],dic[key]])
            print('key：'+str(key)+' '+'begin:' +
                  str(dic[key][0])+' '+'end:'+str(dic[key][1])+' '+'len:'+str(dic[key][2])+' count:'+str(dic[key])+"\n")
            fw.write('key：'+str(key)+' '+'begin:' +
                     str(dic[key])+' '+'end:'+str(dic[key])+' '+'len:'+str(dic[key])+' count:'+str(dic[key])+"\n")
        fw.close()
        csvF.close()
        dic.clear()
        N -= 1


if __name__ == "__main__":
    csvF = open('csvF.csv', 'w+', newline="")
    csvwriter = csv.writer(csvF)
    csvwriter.writerow(['key', 'begin', 'end', 'size', 'packages'])
    csvF.close()
    cp(100)
