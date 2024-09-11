import json
import os
import re 
from datetime import datetime
#Load the data
data = []
fileList = os.listdir('Data/osv_PyPI')
for file in fileList:
    with open('Data/osv_PyPI/' + file) as f:
        data.append(json.load(f))

count_with_aliases = 0
time_list={}
source_list = {}

for item in data:
    if "published" in item:
        try:
            time_list[item['id']] = datetime.strptime(item['published'], "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            time_list[item['id']] = datetime.strptime(item['published'], "%Y-%m-%dT%H:%M:%S.%fZ")
    if 'aliases' in item:
        count_with_aliases += 1
        for alias in item['aliases']:
            source = alias.split('-')[0]
            if source in source_list:
                source_list[source] += 1
            else:
                source_list[source] = 1

print('aliases比例' , count_with_aliases/len(data))
print('source_list:', source_list)

source = list(source_list.keys())

#获取发布时间最早和最晚的漏洞
time_list = sorted(time_list.items(), key=lambda x:x[1])
print('最早发布时间:', time_list[0])
print('最晚发布时间:', time_list[-1])


