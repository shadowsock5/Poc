```
PS C:\Users\Administrator> python3 D:\repos\Poc\weblogic\weblogic_t3.py 127.0.0.1 7001
[+] Connecting to 127.0.0.1 port 7001
sending "t3 12.2.1
AS:255
HL:19
MS:10000000

"
received "b'HELO:10.3.6.0.false\nAS:2048\nHL:19\n\n'"
10.3.6.0
PS C:\Users\Administrator>
PS C:\Users\Administrator> python3 D:\repos\Poc\weblogic\weblogic_t3.py 127.0.0.1 7001
[+] Connecting to 127.0.0.1 port 7001
sending "t3 12.2.1
AS:255
HL:19
MS:10000000

"
received "b'HELO:12.2.1.3.0.false\nAS:2048\nHL:19\nMS:10000000\nPN:DOMAIN\n\n'"
12.2.1.3.0
PS C:\Users\Administrator> python3 D:\repos\Poc\weblogic\weblogic_t3.py 127.0.0.1 7001
[+] Connecting to 127.0.0.1 port 7001
sending "t3 12.2.1
AS:255
HL:19
MS:10000000

"
received "b'HELO:12.1.3.0.0.false\nAS:2048\nHL:19\nMS:10000000\n\n'"
12.1.3.0.0
PS C:\Users\Administrator> python3 D:\repos\Poc\weblogic\weblogic_t3.py 127.0.0.1 7001
[+] Connecting to 127.0.0.1 port 7001
sending "t3 12.2.1
AS:255
HL:19
MS:10000000

"
received "b'HELO:12.2.1.4.0.false\nAS:2048\nHL:19\nMS:10000000\nPN:DOMAIN\n\n'"
12.2.1.4.0
PS C:\Users\Administrator> python3 D:\repos\Poc\weblogic\weblogic_t3.py 127.0.0.1 7001
[+] Connecting to 127.0.0.1 port 7001
sending "t3 12.2.1
AS:255
HL:19
MS:10000000

"
received "b'HELO:14.1.1.0.0.false\nAS:2048\nHL:19\nMS:10000000\nPN:DOMAIN\n\n'"
14.1.1.0.0
```
