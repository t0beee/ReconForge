"""ReconForge v5.0 - Wordlists"""

SUBDOMAINS = [
    "www","mail","ftp","admin","blog","dev","api","test","staging","portal",
    "vpn","remote","secure","shop","cdn","app","login","dashboard","support",
    "docs","help","status","beta","old","new","m","mobile","webmail","smtp",
    "pop","imap","ns1","ns2","mx","mx1","mx2","email","cpanel","whm","plesk",
    "webdisk","autodiscover","server","host","web","web1","web2","web3","db",
    "database","sql","mysql","postgres","redis","mongo","elastic","kibana",
    "grafana","prometheus","jenkins","gitlab","jira","confluence","docker",
    "dev1","dev2","uat","qa","sandbox","preview","demo","internal","intranet",
    "preprod","prod","production","release","alpha","rc","auth","sso","oauth",
    "id","identity","accounts","account","register","assets","static","media",
    "images","img","files","upload","uploads","download","backup","api1","api2",
    "rest","graphql","ws","socket","monitor","monitoring","metrics","logs",
    "panel","cp","s3","storage","gateway","proxy","lb","waf","cart","payment",
    "billing","crm","analytics","search","data","feed","ns3","ns4","mail2",
    "app1","app2","app3","srv1","srv2","node1","node2","vault","secrets",
    "stage","backend","frontend","v1","v2","v3","wiki","forum","store","hr",
    "finance","devops","platform","cloud","git","repo","registry","nexus",
    "sonarqube","zabbix","nagios","splunk","kafka","rabbitmq","keycloak",
    "ldap","ad","sftp","office","remote2","vpn2","citrix","rdp","ssh",
    "test2","test3","sandbox2","admin2","api3","cdn2","assets2","media2",
    "management","manage","secure2","beta2","dev3","staging2","web4","app4",
]

PHP_FILES = [
    "admin.php","administrator.php","admin_login.php","login.php","signin.php",
    "signup.php","register.php","logout.php","auth.php","config.php",
    "configuration.php","settings.php","setup.php","install.php","upgrade.php",
    "backup.php","export.php","import.php","phpinfo.php","info.php","test.php",
    "debug.php","api.php","ajax.php","upload.php","uploader.php","download.php",
    "db.php","database.php","index.php","home.php","search.php","shell.php",
    "cmd.php","command.php","exec.php","c99.php","r57.php","b374k.php","wso.php",
    "phpmyadmin/index.php","pma/index.php","wp-login.php","xmlrpc.php",
    "reset.php","forgot.php","password.php","profile.php","manage.php",
    "panel.php","dashboard.php","process.php","handler.php","request.php",
    "connect.php","wp-config.php","error.php","404.php","maintenance.php",
]

DIRECTORIES = [
    "admin","administrator","login","panel","dashboard","manage","management",
    "api","v1","v2","v3","backup","backups","bak","old","archive","upload",
    "uploads","files","media","images","static","assets","config","settings",
    "db","database","phpmyadmin","pma","test","dev","staging","temp","tmp",
    "cache","log","logs","include","includes","lib","src","app","user","users",
    "account","accounts","search","security","shell","cgi-bin","scripts","bin",
    ".git",".svn",".env","server-status","phpinfo","wp-admin","wp-content",
    "wp-includes","wp-json","secret","secrets","private","hidden","internal",
    "data","export","import","install","setup","deploy","vendor","backup-db",
    "console","api-docs","swagger","actuator","metrics","health","status",
]

WAF_SIGNATURES = {
    "Cloudflare":        ["cloudflare","cf-ray","__cfduid","cf-cache-status"],
    "AWS WAF":           ["awswaf","x-amzn-requestid","x-amz-cf-id"],
    "Akamai":            ["akamai","akamaighost","x-akamai-transformed"],
    "Sucuri":            ["sucuri","x-sucuri-id","x-sucuri-cache"],
    "Imperva/Incapsula": ["incapsula","visid_incap","nlbi_","x-iinfo"],
    "F5 BIG-IP":         ["ts01","bigipserver","f5-bigip"],
    "Barracuda":         ["barra_counter_session","barracuda"],
    "ModSecurity":       ["mod_security","modsecurity","NOYB"],
    "Wordfence":         ["wordfence","wfvt_"],
    "Fortinet":          ["fortigate","forticare"],
}

TOP_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
    3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL", 5900:"VNC",
    6379:"Redis", 8080:"HTTP-Alt", 8443:"HTTPS-Alt", 8888:"Dev-Server",
    9200:"Elasticsearch", 27017:"MongoDB",
}

PORT_RISK = {
    21:"HIGH", 22:"MEDIUM", 23:"CRITICAL", 25:"HIGH", 53:"MEDIUM",
    80:"LOW", 110:"HIGH", 143:"HIGH", 443:"INFO", 445:"CRITICAL",
    3306:"CRITICAL", 3389:"CRITICAL", 5432:"HIGH", 5900:"HIGH",
    6379:"CRITICAL", 8080:"MEDIUM", 8443:"MEDIUM", 8888:"MEDIUM",
    9200:"CRITICAL", 27017:"CRITICAL",
}

PORT_REASON = {
    21:"FTP transmits credentials in plaintext, often allows anonymous login",
    22:"SSH is a common brute-force target — check for weak passwords",
    23:"Telnet is obsolete and sends ALL data including passwords in plaintext",
    25:"Open SMTP may allow mail relay abuse or spam",
    53:"Open DNS may allow zone transfer or amplification attacks",
    80:"Unencrypted HTTP — upgrade to HTTPS",
    110:"POP3 transmits email credentials in plaintext",
    143:"IMAP transmits email credentials in plaintext",
    443:"Standard HTTPS — check certificate and headers",
    445:"SMB directly exposed — EternalBlue/ransomware high risk",
    3306:"MySQL database exposed to internet — critical risk",
    3389:"RDP exposed — BlueKeep, brute-force, ransomware target",
    5432:"PostgreSQL exposed to internet",
    5900:"VNC remote desktop — often weak or no authentication",
    6379:"Redis usually has no authentication by default",
    8080:"Alternative HTTP port — could be dev/proxy server",
    8443:"Alternative HTTPS port — check for misconfigurations",
    8888:"Jupyter or dev server possibly exposed",
    9200:"Elasticsearch has no auth by default — data exposure risk",
    27017:"MongoDB has no auth by default — data exposure risk",
}

SECURITY_HEADERS = [
    "Strict-Transport-Security","Content-Security-Policy",
    "X-Frame-Options","X-Content-Type-Options",
    "Referrer-Policy","Permissions-Policy","X-XSS-Protection",
]

HEADER_RISK = {
    "Strict-Transport-Security": ("HIGH",   "Browsers can be tricked into using HTTP — enables MITM attacks"),
    "Content-Security-Policy":   ("HIGH",   "No script source restrictions — XSS attacks can execute freely"),
    "X-Frame-Options":           ("MEDIUM", "Site can be embedded in iframes — clickjacking attacks possible"),
    "X-Content-Type-Options":    ("MEDIUM", "Browser may misinterpret file types — MIME sniffing attacks"),
    "Referrer-Policy":           ("LOW",    "Browser sends full URL in Referer header — information leakage"),
    "Permissions-Policy":        ("LOW",    "No restrictions on browser features like camera/mic/location"),
    "X-XSS-Protection":          ("LOW",    "Old XSS filter not enabled — minimal impact on modern browsers"),
}

TECH_SIGNATURES = {
    "WordPress":  ["wp-content","wp-includes","wordpress"],
    "Drupal":     ["drupal","sites/all","sites/default"],
    "Joomla":     ["joomla","/components/com_"],
    "PHP":        ["x-powered-by: php"],
    "ASP.NET":    ["x-aspnet-version","asp.net"],
    "Django":     ["csrfmiddlewaretoken"],
    "Laravel":    ["laravel_session"],
    "React":      ["_next","__next","react-dom"],
    "Angular":    ["ng-version","angular"],
    "Vue.js":     ["__vue"],
    "jQuery":     ["jquery"],
    "Bootstrap":  ["bootstrap"],
    "Nginx":      ["nginx"],
    "Apache":     ["apache"],
    "Cloudflare": ["cloudflare","cf-ray"],
    "IIS":        ["x-powered-by: asp","microsoft-iis"],
    "Node.js":    ["x-powered-by: express"],
    "Ruby/Rails": ["x-runtime","x-powered-by: phusion"],
}

WP_PATHS = [
    "wp-login.php","wp-admin/","xmlrpc.php","readme.html","license.txt",
    "wp-config.php.bak","wp-config.php.old","wp-content/debug.log",
    "wp-json/wp/v2/users","?author=1","?author=2","?author=3",
    "wp-content/plugins/","wp-content/themes/","wp-content/uploads/",
    "wp-admin/readme.html","feed/","wp-cron.php","wp-signup.php",
]
