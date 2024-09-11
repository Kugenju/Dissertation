import json
import os

root = 'Data/cvelistV5-main/cvelistV5-main/cves'
cve_list = {}
for fold in os.listdir(root):
    for subfold in os.listdir(root + '/' + fold):
        for file in os.listdir(root + '/' + fold + '/' + subfold):
            with open(root + '/' + fold + '/' + subfold + '/' + file, encoding='utf-8') as f:
                cve = json.load(f)
                cve_id = os.path.splitext(file)[0]
                #判断cve["containers"]["cna"]["providerMetadata"]["dateUpdated"]在不在cve中
                if "containers" not in cve or "cna" not in cve["containers"] or "providerMetadata" not in cve["containers"]["cna"] or "dateUpdated" not in cve["containers"]["cna"]["providerMetadata"]:
                    continue
                #获取发布时间
                cve_list[cve_id] = cve["containers"]["cna"]["providerMetadata"]["dateUpdated"]
#将结果写入文件
with open('Data/cve_list.json', 'w') as f:
    json.dump(cve_list, f)

# #获取发布时间
#                 format = ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"]
#                 for fmt in format:
#                     try:
#                         published_time = datetime.strptime(cve["containers"]["cna"]["providerMetadata"]["dateUpdated"], fmt)
#                         break
#                     except ValueError:
#                         pass