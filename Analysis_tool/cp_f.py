
import scapy_http.http
import scapy.all as scapy
import scapy
import string as string
import socketserver
import time
import threading
from collections import defaultdict

threaten=False
ip_th=""
dic = defaultdict(list)
dic_believing=defaultdict(list)

def cp():
    print("抓包线程启动")
    while 1:
        dpkt = scapy.all.sniff(count=10)
        #pktdump = scapy.all.PcapWriter("demo.pcap", append=True, sync=True)
        # pktdump.write(dpkt)
        # pktdump.close()
        #packets = rdpcap("demo.pcap")
        # type(dpkt)
        lenI = 0
        for data in dpkt:
            timeI = data.time
            time = str(timeI)
            if not hasattr(data, 'len'):
                lenI = 0
            else:
                lenI += data.len
            len = str(lenI)
            if data.haslayer("IP"):
                ip_dstI = data["IP"].dst
                ip_srcI = data["IP"].src
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
                continue
                # 获取某一层的原始负载用.payload.original
                tcp_srcportI = data["UDP"].sport
                tcp_dstportI = data["UDP"].dport
                tcp_srcport = str(tcp_srcportI)
                tcp_dstport = str(tcp_dstportI)
            #print('src_port：'+str(tcp_srcport)+' dst_port：'+str(tcp_dstport))
            if data.haslayer("IP") and (data.haslayer("TCP") or data.haslayer("UDP")):
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
                dic[HASH][1]=time
                dic[HASH][2]=str(int(dic[HASH][2])+lenI)
            else:
                dic[HASH].append(time)
                dic[HASH].append("timing...")
                dic[HASH].append(len)
            global threaten
            global ip_th
            if ip_src <= ip_dst:
                if(int(dic[HASH][2])>=80000):
                    flag=True
                    for item in dic_believing:
                        for i in item:
                            if i==ip_dst:
                                flag=False
                    threaten=flag
                    if threaten:
                        print("发现威胁:"+ip_src)
                        ip_th=ip_dstI
            elif ip_src > ip_dst:
                if(int(dic[HASH][2])>=80000):
                    flag=True
                    for item in dic_believing:
                        for i in item:
                            if i==ip_src:
                                flag=False
                    threaten=flag
                    if threaten:
                        print("发现威胁:"+ip_src)
                        ip_th=ip_srcI
        #fw = open('result.txt', 'w+', encoding='utf-8')
        #for key in dic.keys():
        #        #print("受到来自:"+ip_th+"的流量威胁")
        #    print('key：'+str(key)+' '+'begin:' +
        #         str(dic[key][0])+' '+'end:'+str(dic[key][1])+' '+'len:'+str(dic[key][2])+"\n")
        #    fw.write('key：'+str(key)+' '+'begin:' +
        #         str(dic[key][0])+' '+'end:'+str(dic[key][1])+' '+'len:'+str(dic[key][2])+"\n")
        #fw.close()
#服务端

class MyServer(socketserver.BaseRequestHandler):
    def handle(self):
        print("收到来自:"+self.client_address[0]+"的连接")
        #通讯循环
        str='输入设备号'.encode("utf_8")
        self.request.sendall(str)
        while True:
            try:
                data=self.request.recv(1024)
                print('客户端连接的摄像头ID是： ',data.decode('utf-8'))
                ID=data.decode('utf-8')
                dic_believing[ID].append(self.client_address[0]) #为设备增加信任IP
                break
            except Exception as e:
                print(e)
                break
        while True:
            #收消息
            try:
                #data=self.request.recv(1024)
                #print('收到客户端的消息是： ',data.decode('utf-8'))
                #发消息
                global threaten
                global ip_th
                if threaten:
                    data='发现威胁:'+ip_th
                    self.request.sendall(data.encode())
                    threaten=False
                    ip_th=""
                    time.sleep(5)
                #self.request.sendall(data.upper())   #循环发消息
            except Exception as e:
                print(e)
                break

if __name__ == '__main__':
    T=threading.Thread(target=cp)
    T.start()
    s=socketserver.ThreadingTCPServer(("",8089),MyServer)  #多线程的TCP服务端，可以同时开启多个任务等着客户端来连，来一个请求就处理一个
    s.serve_forever()
    T.join()
    