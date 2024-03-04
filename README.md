# gress
Turn Nessus XML into grep-able output; IP address, Port, CVSS Score, Nessus Vuln Title.
``` 
GRep-able nESSus (gress)
---------------------------------------------------
Parse Nessus into a Bash Grep-able syntax
---------------------------------------------------

The following syntax is for operational flags:
---------------------------------------------------
-n	 | Nessus XML file to parse
-v	 | Parse a single vulnerbility or issue for the Nessus XML file


The following shows examples of tool usage:
---------------------------------------------------
./gress -n my_scan_lfi55d.nessus
./gress -n my_scan_lfi55d.nessus -v "SSL Weak Cipher Suites Supported"
./gress -n my_scan_lfi55d.nessus | cut -f 4- -d "," | sort -u | xargs -i ./gress -n my_scan_lfi55d.nessus -v {}
```
