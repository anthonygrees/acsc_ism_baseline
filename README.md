# acsc_ism_baseline
Australian Government Information Security Manual (ISM) InSpec Profile

### About
The Australian Cyber Security Centre within the Australian Signals Directorate produces the Australian Government Information Security Manual (ISM). The purpose of the ISM is to outline a cyber security framework that organisations can apply, using their risk management framework, to protect their information and systems from cyber threats.
https://www.cyber.gov.au/ism

This is a Chef InSpec profile that takes the ISM guidelines and runs them as code.

### Execute
First authenticate to your Chef Automate complaince server
```bash
 inspec compliance login https://your-chef-automate.chef-demo.com --user admin --insecure --token
'<token>'
```

Next run the profile
```bash
inspec exec .
```
