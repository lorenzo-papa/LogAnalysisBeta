# LogAnalysisBeta

Welcome! With LogAnalysisTool it is possible to perform *forensic* analysis of *Wtmp, Btmp and Secure log* (auth.log) files.
Specifically, sessions and access attempts to the system are extracted, to detect the presence of eventual attack patterns
(*Brute Force or Spray*) and the related (eventual) *malicious logins*. Moreover, it is possible to search from public sources
details about the attacking IPs and/or possible IPs of interest. Finally, it ispossible to search by keywords or by time filters
within (non-binary) files.

pwd PDF: cybersecurity

# Commands:
- {grep,rgrep,time,rtime,single_ip_search,multiple_ip_search,binary_parse,login_search,secure_log_search}

# Analysis:
- Through the **<binary_parse>** command it is possible to analyze Wtmp and Btmp files individually. Specifically, in the first case
all the system sessions will be extracted, while in the second case the system access attempts will be searched to identify
attack patterns (Brute Force and Spray) and statistical information about these attempts. The search for information about the
attacking IPs will be performed automatically.
- Through the **<login_search>** command it is possible to analyze a couple of Wtmp and Btmp files. All the system sessions and all
system access attempts will be searched in order to identify attack patterns (Brute Force and Spray), statistical information
about these attempts and malicious logins. The search for information about the attacking IPs will be performed automatically.
- Through the **<secure_log_search>** command it is possible to analyze auth.log (or secure) files. All the system sessions and all
system access attempts will be searched in order to identify attack patterns (Brute Force and Spray), statistical information
about these attempts and malicious logins. The search for information about the attacking IPs will be performed automatically.

#Utility:
- The ***<grep>*** command is used to find keywords within a single readable (non-binary) file. It performs a line-by-line check and
extracts only those lines that match the requested pattern.
- The ***<rgrep>*** command is used to find keywords within readable (non-binary) files in a directory. It performs a line-by-line check
and extracts only those lines that match the requested pattern.
- The ***<time>*** command is used to filter logs within a single readable (non-binary) file through a requested time interval. It
performs a line-by-line check and extracts only those lines that match the requested pattern.By default the <end time> is the
locatime of the machine on which the execution is invoked
- The ***<rtime>*** command is used to filter logs within readable (non-binary) files in a directory through a requested time interval.
It performs a line-by-line check and extracts only those lines that match the requested pattern.By default the <end time> is the
locatime of the machine on which the execution is invoked
- The ***<single_ip_search>*** command is used to get informations of a single IP address: IP geolocalization, public info (Description,
CN, ASN, etc), reputation, open ports and CVE vulnerabilities.It uses IP2Geotools, AbuseIPDB and Shodan.
- The **<multiple_ip_search>** command is used to get informations of multiple IP addresses: IP geolocalization, public info
(Description, CN, ASN, etc), reputation, open ports and CVE vulnerabilities.It uses IP2Geotools, AbuseIPDB and Shodan. Due to
the possible large amount of IPs requested, it presents the output data in a different format than the single-ip-search.

Hope you will enjoy it! :)
