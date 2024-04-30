# LoonSecurity

Loon Cybersecurity or LoonSec is a set of tools to help Application Security and Vulnerability Management engineers quickly solve complex threat detections and provide up to the minute industry analytics.

One area that many scanners and detections fail to lack is having up to date CVE information from NVD or MITRE. The data is also disparte as vendors such as Microsoft intentionally fail to release correct data and defeer to their own systems. Further other 3rd party services contain exposure, exploit, and other data that is helpful in determining your personal or organizational risk.

# Features

 - Extract and augument NVD Vulnerabilities from String Objects
 - Extract and augument NVD Vulnerabilities from JSON/Dictionaries
 - Extract and augument NVD Vulnerabilities from other services SDKs.
 - Gather Latest NVD CVE Vulnerability infromation from NVD, LoonSec (pending), or other supported 3rd party Vulnerability Providers
 - Given an NVD CVE ID gather information from 3rd parties about exposure, exploitability, and measurements against.
 - Optimized to work with the NVD API and stability and capacity issues that may present themselves in their API.

# Use Cases

## Setup
```python
from LoonSec import NVDValidator
s = //Crowdstrike Vulnerability Dict
feather = NVDValidator(nvd_api_key="YourKey")
vulns = feather.find_vuln_ids(s)
print(vulns)
```

Response:

```json
{
 "key_vulns": ["CVE-2021-11111"],
 "found_vulns": ["CVE-2021-11111", "CVE-2022-99999"]
}
```
## Add NVD Vulnerability to 3rd party scanner result

## Query NVD for a Record

## Feed a large set of CVE's

 # Documentation

# Support LoonSecurity
For the API services Open Collective will be the target platform for funding the API services and further development. 

Any issues respond in the issues section of this repository.

 # Security

 Please report any security concerns with this package using the open source TideLift platform https://tidelift.com/docs/security

 # License

Distributed under the terms of the MIT license, This Repository is free and open source software.
