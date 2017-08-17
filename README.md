# Deduplication of yara rules

This script takes a path of yara rules, and goes over them to identify duplicate rules if any. It then organises the output at a different path.

It also organises & creates:
1. index file (for all rules under all folders)
2. individual index files (for each folder of rules)
3. one single file with all the rules squeezed in

## Requirements

1. Python 2.7
2. yara-python

## Example

```
$ python dedupe_yara_rule.py -p yara/
Yara Rules deduper v0.1
marirs (at) gmail.com / Licence: GPL
Disclaimer: This script is provided as-is without any warranty. Use at your own Risk :)
Report bugs/issues at: https://github.com/marirs/dedupe_yara_rule/issues

[*] '/Users/macuser/yara/yara_new' set to be the output directory!
[*] Total files to process: 415 files in 12 dirs.
[-] No yara rules found in Antidebug_AntiVM_index.yar
[-] No yara rules found in Crypto_index.yar
[-] No yara rules found in CVE_Rules_index.yar
[-] No yara rules found in email_index.yar
[-] No yara rules found in Exploit-Kits_index.yar
[-] No yara rules found in index.yar
[-] No yara rules found in index_w_mobile.yar
[-] No yara rules found in Malicious_Documents_index.yar
[-] No yara rules found in malware_index.yar
[-] No yara rules found in Mobile_Malware_index.yar
[-] No yara rules found in Packers_index.yar
[-] No yara rules found in Webshells_index.yar
[*] Total # of Rules: 12284
[*] Total # of Duplicate Rules: 0
-----------------------------------
[*] Checking import modules...
 -> import "hash": PASS
 -> import "pe": PASS
 -> import "cuckoo": You dont have this module!
 -> import "math": PASS
 -> import "androguard": You dont have this module!
-----------------------------------
[*] Creating index files...
 -> ./yara_new/deduped_rules/all_in_one_rules.yar
 -> ./yara_new/deduped_rules/index.yar
 -> ./yara_new/deduped_rules/Antidebug_AntiVM_index.yar
 -> ./yara_new/deduped_rules/Crypto_index.yar
 -> ./yara_new/deduped_rules/CVE_Rules_index.yar
 -> ./yara_new/deduped_rules/email_index.yar
 -> ./yara_new/deduped_rules/Exploit-Kits_index.yar
 -> ./yara_new/deduped_rules/Malicious_Documents_index.yar
 -> ./yara_new/deduped_rules/malware_index.yar
 -> ./yara_new/deduped_rules/Mobile_Malware_index.yar
 -> ./yara_new/deduped_rules/Packers_index.yar
 -> ./yara_new/deduped_rules/utils_index.yar
 -> ./yara_new/deduped_rules/Webshells_index.yar
-----------------------------------
[*] Verifying rules...
 -> ./yara_new/deduped_rules/malware/MALW_Magento_backend.yar(146): syntax error, unexpected _IDENTIFIER_, expecting _CONDITION_ [skipped file due to compile error...]
[*] All rules organised in /Users/macuser/yara/yara_new
$
```

