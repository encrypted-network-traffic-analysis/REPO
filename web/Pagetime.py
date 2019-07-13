import json
import csv
from collections import defaultdict

csvF=open('Time.csv','w+',newline="")
csvwriter=csv.writer(csvF)
csvwriter.writerow(['网页','起始时间','终止时间'])
time_web=defaultdict(list)
fr=open('web.txt','r',encoding='UTF-8')
for row in fr:
    row = row.strip('\n')
    fj=open(row+'.json',encoding='UTF-8')
    data=json.load(fj)
    Begin=""
    End=""
    connection=defaultdict(list)
    if 'pages' in data['log']:
        for p in data['log']['pages']:
            if 'startedDateTime' in p:
                Begin=p['startedDateTime']
    if 'entries' in data['log']:
        for t in data['log']['entries']:
            TB=""
            TN=""
            if 'startedDateTime' in t:
                if Begin=="":
                    Begin=t['startedDateTime']
                End=t['startedDateTime']
                for i in range(0,len(Begin)-2):
                    if i==4 or i==7 or i==10 or i==13 or i==16 or i==19:
                        continue
                    TB+=Begin[i]
                for i in range(0,len(End)-2):
                    if i==4 or i==7 or i==10 or i==13 or i==16 or i==19:
                        continue
                    TN+=End[i]
            Time=int(TB)
            TimeN=int(TN)
            if 'connection' in t and 'time' in t:
                if t['connection'] in connection:
                    connection[t['connection']][1]=TimeN+t['time']
                else:
                    connection[t['connection']].append(TimeN)
                    connection[t['connection']].append(TimeN+t['time'])
                    connection[t['connection']].append(TimeN+t['time'])
    time_web[row].append(Begin)
    time_web[row].append(End)
    time_web[row].append(connection)
    print([str(row),str(Begin),str(End)])
    csvwriter.writerow([str(row),str(Begin),str(End)])
    C=[]
    for key in connection.keys():
        print(key,connection[key])   
        C.append([key,connection[key]])
    csvwriter.writerow(C)
