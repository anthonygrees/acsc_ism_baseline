# Australian Government Information Security Manual (ISM) InSpec Profile Baseline

### About
The Australian Cyber Security Centre within the Australian Signals Directorate produces the Australian Government Information Security Manual (ISM). The purpose of the ISM is to outline a cyber security framework that organisations can apply, using their risk management framework, to protect their information and systems from cyber threats.
https://www.cyber.gov.au/ism

This is a Chef InSpec profile that takes the ISM guidelines and runs them as code.

### Execute
Clone the repo
```bash
git clone https://github.com/anthonygrees/acsc_ism_baseline

cd acsc_ism_baseline
```

First authenticate to your Chef Automate complaince server
```bash
 inspec compliance login https://your-chef-automate.chef-demo.com --user workstation-1 --insecure --token
'<token>'
```

Next run the profile
```bash
inspec exec .
```
Your output will be displayed on the STDOUT as:
```bash
Profile: DevSec Windows Patch Baseline (windows-patch-baseline)
Version: 0.4.0
Target:  local://

  [PASS]  verify-kb: ACSC ISM 1143, 1493, 1144, 0940 - System patching
     [PASS]  0 is expected to eq 0
  [PASS]  important-count: ACSC ISM 1143, 1493, 1144, 0940 - System patching
     [PASS]  0 is expected to eq 0
  [PASS]  optional-count: ACSC ISM 0300, 0298, 0303, 1497, 1498, 1499, 1500 - System patching
     [PASS]  0 is expected to eq 0


Profile Summary: 10 successful controls, 8 control failures, 0 controls skipped
Test Summary: 13 successful, 28 failures, 0 skipped
```

### Report
To report into Chef Automate
```bash
inspec exec . --json-config inspec.json
```

![ISM Report](/images/ism-report.png)

### Source
Australian Government Information Security Manual - [PDF](https://www.cyber.gov.au/sites/default/files/2020-06/ISM%20-%20List%20of%20Security%20Controls%20%28June%202020%29.xml)

### Chef InSpec
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
