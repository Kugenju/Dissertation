import requests
import json
from datetime import datetime, timedelta

# 定义起始和结束时间
start_date = datetime(2021, 8, 4, 13, 0, 0)
end_date = datetime(2024, 11, 19, 13, 36, 0)

# 定义时间间隔为两个月
delta = timedelta(days=60)

# 循环获取数据
current_date = start_date
while current_date < end_date:
    next_date = current_date + delta
    if next_date > end_date:
        next_date = end_date
    
    # 格式化日期
    start_str = current_date.strftime("%Y-%m-%dT%H:%M:%S.000%z")
    end_str = next_date.strftime("%Y-%m-%dT%H:%M:%S.000%z")
    
    # 构建URL
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate={start_str}&lastModEndDate={end_str}"
    
    # 发送HTTP GET请求
    response = requests.get(url)
    
    # 检查请求是否成功
    if response.status_code == 200:
        # 将响应内容解析为JSON
        data = response.json()
        
        # 将数据保存到文件
        filename = f'cves_data_{current_date.strftime("%Y%m%d")}_to_{next_date.strftime("%Y%m%d")}.json'
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
    else:
        print(f"请求失败，状态码: {response.status_code}")
    
    # 更新当前日期
    current_date = next_date