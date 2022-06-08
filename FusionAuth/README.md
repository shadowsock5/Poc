## fusionauth-samlv2
ref: https://github.com/FusionAuth/fusionauth-samlv2
### [CVE-2020-12676] authentication bypass, aka a "Signature exclusion attack"
fusionauth-samlv2 0.2.3
> FusionAuth fusionauth-samlv2 0.2.3 allows remote attackers to forge messages and bypass authentication via a SAML assertion that lacks a Signature element, aka a "Signature exclusion attack".

Ref:
- https://www.compass-security.com/fileadmin/Research/Advisories/2020-06_CSNC-2020-002_FusionAuth_Signature_Exclusion_Attack.txt

### [CVE-2021-27736] XXE attacks via a forged AuthnRequest or LogoutRequest
fusionauth-samlv2 <0.5.4
> FusionAuth fusionauth-samlv2 before 0.5.4 allows XXE attacks via a forged AuthnRequest or LogoutRequest because parseFromBytes uses javax.xml.parsers.DocumentBuilderFactory unsafely.

Ref: 
- https://www.compass-security.com/fileadmin/Research/Advisories/2021-03_CSNC-2021-004_FusionAuth_SAML_Library_XML_External_Entity.txt

## FusionAuth
### [CVE-2020-7799] FusionAuth command execution via Apache Freemarker Template
FusionAuth 1.10 and lower
> An authenticated attacker with enough privileges to access the template editing functions (either site templates or e-mail templates) in the FusionAuth dashboard can execute commands on the underlying operating system using the Apache FreeMarker Expression language.

Ref: 
- https://lab.mediaservice.net/advisory/2020-03-fusionauth.txt
- https://blog.csdn.net/caiqiiqi/article/details/104186575
- https://github.com/CompassSecurity/SAMLRaider
