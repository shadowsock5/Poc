### [CVE-2021-39226] Grafana Snapshot Authentication Bypass

影响范围：
- Grafana instances up to 7.5.11 and 8.1.5
```
/api/snapshots/:key
/api/snapshots-delete/:deleteKey
/dashboard/snapshot/:key
```

>   description: Grafana instances up to 7.5.11 and 8.1.5 allow remote unauthenticated users to view the snapshot associated with the lowest database key by accessing the literal paths /api/snapshot/:key or /dashboard/snapshot/:key. If the snapshot is in public mode, unauthenticated users can delete snapshots by accessing the endpoint /api/snapshots-delete/:deleteKey. Authenticated users can also delete snapshots by accessing the endpoints /api/snapshots-delete/:deleteKey, or sending a delete request to /api/snapshot/:key, regardless of whether or not the snapshot is set to public mode (disabled by default).


### [CVE-2021-43813]/[CVE-2021-43815]

any low priviledged user (eg: VIEWER) can abuse this vulnerability to read arbitrary markdown files in the server.

- https://securitylab.github.com/advisories/GHSL-2021-1053_Grafana/


### [CVE-2021-43798] Grafana v8.x Arbitrary File Read

影响范围：
- Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions)
```
/public/plugins/alertlist/../../../../../../../../../../../../../../../../../../../etc/passwd
```

### Grafana RCE?
- [Grafana RCE via SMTP server parameter injection](https://hackerone.com/reports/1200647)

## Ref

- [Authentication bypass for viewing and deletions of snapshots](https://github.com/advisories/GHSA-69j6-29vr-p3j9)
- https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-39226.yaml
- https://github.com/jas502n/Grafana-VulnTips
- https://github.com/projectdiscovery/nuclei-templates/blob/a19b941193d7f604b2b4a8b2092a227290d9c77d/cves/2021/CVE-2021-43798.yaml
- https://blog.riskivy.com/grafana-%e4%bb%bb%e6%84%8f%e6%96%87%e4%bb%b6%e8%af%bb%e5%8f%96%e6%bc%8f%e6%b4%9e%e5%88%86%e6%9e%90%e4%b8%8e%e6%b1%87%e6%80%bbcve-2021-43798/
