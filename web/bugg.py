import webbrowser as web
import time
import os
import random
count=random.randint(2,4)
fr=open('web.txt','r',encoding='UTF-8')
chromePath = r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
web.register('chrome', None, web.BackgroundBrowser(chromePath))

for row in fr:
    row=row.strip('\n')
    web.get('chrome').open(str(row),new=1,autoraise=True)
    time.sleep(10)