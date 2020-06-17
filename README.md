# acsc_ism_baseline
Australian Government Information Security Manual (ISM) InSpec Profile


### How to run the profile
First authenticate to your Chef Automate complaince server
```bash
 inspec compliance login https://your-chef-automate.chef-demo.com --user admin --insecure --token
'<token>'
```

Next run the profile
```bash
inspec exec .
```
