# PyADRecon
Python3 implementation of [ADRecon](https://github.com/sense-of-security/ADRecon)

## Usage

````py
usage: pyadrecon.py [-h] [--generate-excel-from CSV_DIR] [-dc DOMAIN_CONTROLLER] [-u USERNAME] [-p PASSWORD]
                    [-d DOMAIN] [--auth {ntlm,kerberos}] [--ssl] [--port PORT] [-o OUTPUT]
                    [--page-size PAGE_SIZE] [--threads THREADS] [--dormant-days DORMANT_DAYS]
                    [--password-age PASSWORD_AGE] [--only-enabled] [--collect COLLECT] [--no-excel] [-v]

PyADRecon - Python Active Directory Reconnaissance Tool

options:
  -h, --help            show this help message and exit
  --generate-excel-from CSV_DIR
                        Generate Excel report from CSV directory (standalone mode, no AD connection needed)
  -dc, --domain-controller DOMAIN_CONTROLLER
                        Domain Controller IP or hostname
  -u, --username USERNAME
                        Username for authentication
  -p, --password PASSWORD
                        Password for authentication
  -d, --domain DOMAIN   Domain name (e.g., DOMAIN.LOCAL)
  --auth {ntlm,kerberos}
                        Authentication method (default: ntlm)
  --ssl                 Use SSL/TLS (LDAPS)
  --port PORT           LDAP port (default: 389, use 636 for LDAPS)
  -o, --output OUTPUT   Output directory (default: PyADRecon-Report-<timestamp>)
  --page-size PAGE_SIZE
                        LDAP page size (default: 500)
  --threads THREADS     Number of threads (default: 10)
  --dormant-days DORMANT_DAYS
                        Days for dormant account threshold (default: 90)
  --password-age PASSWORD_AGE
                        Days for password age threshold (default: 30)
  --only-enabled        Only collect enabled objects
  --collect COLLECT     Comma-separated modules to collect (default: all except kerberoast,acls)
  --no-excel            Skip Excel report generation
  -v, --verbose         Verbose output

Examples:
  # Basic usage with NTLM authentication
  pyadrecon.py -dc 192.168.1.1 -u admin -p password123 -d DOMAIN.LOCAL

  # With Kerberos authentication
  pyadrecon.py -dc dc01.domain.local -u admin -p password123 -d DOMAIN.LOCAL --auth kerberos

  # Only collect specific modules
  pyadrecon.py -dc 192.168.1.1 -u admin -p pass -d DOMAIN.LOCAL --collect users,groups,computers

  # Output to specific directory
  pyadrecon.py -dc 192.168.1.1 -u admin -p pass -d DOMAIN.LOCAL -o /tmp/adrecon_output

  # Generate Excel report from existing CSV files (standalone mode)
  pyadrecon.py --generate-excel-from /path/to/CSV-Files -o report.xlsx
````

## Acknowledgements

Many thanks to [S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t/AI-Coded-scripts) and Claude for a first version.
