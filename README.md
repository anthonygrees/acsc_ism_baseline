# Australian Government Information Security Manual (ISM) InSpec Profile Baseline

## About
The Australian Cyber Security Centre within the Australian Signals Directorate produces the Australian Government Information Security Manual (ISM). The purpose of the ISM is to outline a cyber security framework that organisations can apply, using their risk management framework, to protect their information and systems from cyber threats.
https://www.cyber.gov.au/ism

This is a Chef InSpec profile that takes the ISM guidelines and runs them as code.

## Execute
Clone the repo
```bash
git clone https://github.com/anthonygrees/acsc_ism_baseline

cd acsc_ism_baseline
```

First authenticate to your Chef Automate complaince server
```bash
 inspec compliance login https://your-chef-automate.chef-demo.com --user admin --insecure --token
'<token>'
```

Next run the profile
```bash
inspec exec .
```

## Report
To report into Chef Automate
```bash
inspec exec . --json-config inspec.json
```

![ISM Report](/images/ism-report.png)

## Source
Australian Government Information Security Manual - [PDF](https://www.cyber.gov.au/sites/default/files/2020-06/ISM%20-%20List%20of%20Security%20Controls%20%28June%202020%29.xml)

## Chef InSpec
Don't have InSpec installed? 

Here you go - [InSpec Link](https://downloads.chef.io/inspec)

## License and Author

* Author:: Anthony Rees <anthony@chef.io>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
