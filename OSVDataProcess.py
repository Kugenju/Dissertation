import json
import os
import re 
from datetime import datetime
import matplotlib.pyplot as plt

#Load the data
data = []
fileList = os.listdir('Data/osv_PyPI')
for file in fileList:
    with open('Data/osv_PyPI/' + file) as f:
        data.append(json.load(f))

count_with_aliases = 0
time_list={}
source_list = {}

def parse_date(date_str):
    formats = ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"]
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            pass
    return None

for item in data:
    if "published" in item:
        time = parse_date(item["published"])
        if time:
            time_list[item['id']] = time
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

with open('Data\cve_list.json', 'r') as f:
    cve_time = json.load(f)
for key in cve_time:
    cve_time[key] = parse_date(cve_time[key])
time_list.update(cve_time)

# #获取发布时间最早和最晚的漏洞
# time_list = sorted(time_list.items(), key=lambda x:x[1])
# print('最早发布时间:', time_list[0])
# print('最晚发布时间:', time_list[-1])

# #绘制source_list的饼图
# plt.figure(figsize=(6,9))
# #选用source_list中前五个数据
# source_list = dict(sorted(source_list.items(), key=lambda x:x[1], reverse=True)[:5])
# labels = source_list.keys()
# sizes = source_list.values()
# plt.pie(sizes, labels=labels, autopct='%1.1f%%')
# plt.title('osv_PyPI Source Distribution')
# plt.axis('equal')
# plt.show()

#CVE、PYSEC、GHSA的共现关系矩阵
co_occurrence_matrix =  {
    'CVE': {'CVE': 0, 'PYSEC': 0, 'GHSA': 0},
    'PYSEC': {'CVE': 0, 'PYSEC': 0, 'GHSA': 0},
    'GHSA': {'CVE': 0, 'PYSEC': 0, 'GHSA': 0}
}

timeSort_matrix={'CVE': {'CVE': 0, 'PYSEC': 0, 'GHSA': 0},
    'PYSEC': {'CVE': 0, 'PYSEC': 0, 'GHSA': 0},
    'GHSA': {'CVE': 0, 'PYSEC': 0, 'GHSA': 0}
} 

time_miss_count = 0

def getFirstTime(aliases, time_list):
    #获取时间最早的aliases
    time = {alias: time_list[alias] for alias in aliases if alias in time_list}
    if len(time) == 0:
        return None
    return sorted(time.items(), key=lambda x:x[1])[0][1]
            

def combat_time(aliases, time_list):
    #获取该条漏洞同情报源中最早的时间并排序返回结果
    cve_ids = [alias for alias in aliases if alias.split('-')[0] == 'CVE'] 
    pysec_ids = [alias for alias in aliases if alias.split('-')[0] == 'PYSEC']
    ghsa_ids = [alias for alias in aliases if alias.split('-')[0] == 'GHSA']
    cve_time = getFirstTime(cve_ids, time_list)
    pysec_time = getFirstTime(pysec_ids, time_list)
    ghsa_time = getFirstTime(ghsa_ids, time_list)
    return cve_time, pysec_time, ghsa_time

def update_timeSort_matrix(cve_time, pysec_time, ghsa_time, timeSort_matrix):
    if cve_time and pysec_time:
        if cve_time < pysec_time:
            timeSort_matrix['CVE']['PYSEC'] += 1
        else:
            timeSort_matrix['PYSEC']['CVE'] += 1
    if cve_time and ghsa_time:
        if cve_time < ghsa_time:
            timeSort_matrix['CVE']['GHSA'] += 1
        else:
            timeSort_matrix['GHSA']['CVE'] += 1
    if pysec_time and ghsa_time:
        if pysec_time < ghsa_time:
            timeSort_matrix['PYSEC']['GHSA'] += 1
        else:
            timeSort_matrix['GHSA']['PYSEC'] += 1

for item in data:
    orphan = item['id'].split('-')[0]
    try:
        item_date = datetime.strptime(item['published'], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        item_date = datetime.strptime(item['published'], "%Y-%m-%dT%H:%M:%S.%fZ")
    if 'aliases' in item:
        sources = [alias.split('-')[0] for alias in item['aliases'] if alias.split('-')[0] in ['CVE', 'PYSEC', 'GHSA']]
        if orphan != 'MAL':
            sources.append(orphan)
        sources = list(set(sources))
        for i in range(len(sources)):
            for j in range(i+1, len(sources)):
                co_occurrence_matrix[sources[i]][sources[j]] += 1
                co_occurrence_matrix[sources[j]][sources[i]] += 1
        #时间排序
        ids = [alias for alias in item['aliases'] if alias.split('-')[0] in ['CVE', 'PYSEC', 'GHSA']]
        if orphan != 'MAL':
            ids.append(item['id'])
        cve_time, pysec_time, ghsa_time = combat_time(ids, time_list)
        #print(cve_time, pysec_time, ghsa_time)
        update_timeSort_matrix(cve_time, pysec_time, ghsa_time, timeSort_matrix)

advantage_matrix = {'CVE': {'CVE': 0, 'PYSEC': 0, 'GHSA': 0},
    'PYSEC': {'CVE': 0, 'PYSEC': 0, 'GHSA': 0},
    'GHSA': {'CVE': 0, 'PYSEC': 0, 'GHSA': 0}
} 

for key in co_occurrence_matrix:
    for subkey in co_occurrence_matrix[key]:
        if key == subkey:
            continue
        advantage_matrix[key][subkey] =timeSort_matrix[key][subkey]/co_occurrence_matrix[key][subkey]
        #百分比
        advantage_matrix[key][subkey] = round(advantage_matrix[key][subkey], 4)
def print_matrix(matrix):
    for key in matrix:
        print(key, matrix[key])

print('co_occurrence_matrix:')
print_matrix(co_occurrence_matrix)
# print('timeSort_matrix:')
# print_matrix(timeSort_matrix)
print('advantage_matrix:')
print_matrix(advantage_matrix)