
import scapy_http.http
import scapy.all as scapy
import scapy
import string as string

dic_begin = {}
dic_end = {}
dic_len = {}
while 1:
    dpkt  = scapy.all.sniff(count = 1000)
    pktdump = scapy.all.PcapWriter("demo.pcap", append=True, sync=True)
    pktdump.write(dpkt)
    pktdump.close()
    #packets = rdpcap("demo.pcap")
    # type(dpkt)

    lenI=0
    for data in dpkt:
        timeI = data.time
        time = str(timeI)
        if not hasattr(data,'len'):
            lenI=0
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
            if HASH in dic_begin:
                dic_end[HASH] = time
            else:
                dic_end[HASH] = time
                dic_begin[HASH] = time
            dic_len[HASH] = len
    fw = open('result.txt', 'w+', encoding='utf-8')
    for key in dic_begin.keys():
        print('key：'+str(key)+' '+'begin:' +
            str(dic_begin[key])+' '+'end:'+str(dic_end[key])+' '+'len:'+str(dic_len[key])+"\n")
        fw.write('key：'+str(key)+' '+'begin:' +
            str(dic_begin[key])+' '+'end:'+str(dic_end[key])+' '+'len:'+str(dic_len[key])+"\n")
    fw.close()
    dic_begin.clear()
    dic_end.clear()
    dic_len.clear()
