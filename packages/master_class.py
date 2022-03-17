class master():

    succeeded = 0  # Number of lines converted
    failed = 0  # Number of lines from input file not converted

    default_app = {
        "ANY": "any",
        "BGP": "junos-bgp",
        "CHARGEN": "junos-chargen",
        "DHCP-Relay": "junos-dhcp-relay",
        "DISCARD": "junos-discard",
        "DNS": "junos-dns",
        "ECHO": "junos-echo",
        "FINGER": "junos-finger",
        "FTP": "junos-ftp",
        "GRE": "junos-gre",
        "GTP": "junos-gtp",
        "H.323": "junos-h323",
        "HTTP": "junos-http",
        "HTTP-EXT": "junos-http-ext",
        "HTTPS": "junos-https",
        "ICMP-ANY": "junos-icmp-all",
        "IDENT": "junos-ident",
        "IKE": "junos-ike",
        "IKE-NAT": "junos-ike-nat",
        "IMAP": "junos-imap",
        "Internet Locator Service": "junos-internet-locator-service",
        "IRC": "junos-irc",
        "L2TP": "junos-l2tp",
        "LDAP": "junos-ldap",
        "LPR": "junos-lpr",
        "MAIL": "junos-mail",
        "MGCP-CA": "junos-mgcp-ca",
        "MGCP-UA": "junos-mgcp-ua",
        "MS-EXCHANGE-DIRECTORY": "junos-ms-rpc-msexchange",
        "MS-EXCHANGE-INFO-STORE": "junos-ms-rpc-msexchange",
        "MS-EXCHANGE-STORE": "junos-ms-rpc-msexchange",
        "MS-IIS-COM": "junos-ms-rpc-iis-com",
        "MS-RPC-ANY": "junos-ms-rpc-any",
        "MS-RPC-EPM": "junos-ms-rpc-epm",
        "MS-SQL": "junos-ms-sql",
        "MSN": "junos-msn",
        "NBDS": "junos-nbds",
        "NBNAME": "junos-nbname",
        "NFS": "junos-nfs",
        "NNTP": "junos-nntp",
        "NS Global": "junos-ns-global",
        "NS Global PRO": "junos-ns-global-pro",
        "NSM": "junos-nsm",
        "NTP": "junos-ntp",
        "OSPF": "junos-ospf",
        "PC-Anywhere": "junos-pc-anywhere",
        "PING": "junos-ping",
        "POP3": "junos-pop3",
        "PPTP": "junos-pptp",
        "RADIUS": "junos-radius",
        "Real Media": "junos-realaudio",
        "RIP": "junos-rip",
        "RSH": "junos-rsh",
        "RTSP": "junos-rstp",
        "SCCP": "junos-sccp",
        "SCTP-ANY": "junos-sctp-any",
        "SIP": "junos-sip",
        "SMB": "junos-smb",
        "SMTP": "junos-mail",
        "SNMP": "udp_161",
        "SQL Monitor": "junos-sql-monitor",
        "SQL*Net V1": "junos-sqlnet-v1",
        "SQL*Net V2": "junos-sqlnet-v2",
        "SSH": "junos-ssh",
        "SYSLOG": "junos-syslog",
        "TALK": "junos-talk",
        "TCP-ANY": "junos-tcp-any",
        "TELNET": "junos-telnet",
        "TFTP": "junos-tftp",
        "UDP-ANY": "junos-udp-any",
        "UUCP": "junos-uucp",
        "VDO Live": "junos-vdo-live",
        "VNC": "junos-vnc",
        "WAIS": "junos-wais",
        "WHOIS": "junos-whois",
        "WINFRAME": "junos-winframe",
        "X-WINDOWS": "junos-x-windows",
        "YMSG": "junos-ymsg"
    }

    default_addr = {
        "Any":  "any"
    }

    ## Dictionaries (Custom Service & Service Groups)
    # For referencing when comes time to convert rules, contains Junos App's and App groups
    service_ns_to_junos = {}  # key = ns_service_name, value = junos app

    # Dictionary for ns multi service protocol to junos application set mapping
    service_grp_to_app_set = {}  # key = ns service name, value = junos app set name

    # Combine all 3 service dictionaries into 1 for ease of lookups in other function. This syntax only value in python >= 3.5
    service_dicts = {} # Create empty and add above 3 service dicts later once populated

    # Empty list to populate below to create address book names and bind to zones
    list_of_zones = []

    # Address name dictionary mapping.  Key = ns address name, value = junos address name
    addresses_ns_to_junos = {}

    # Address group to Junos address set mapping.  Key = ns address grp, value = junos address set
    address_group_ns_to_junos_address_set = {}

    # Address and address group dicts combines for lookups when building sets nested with sets
    address_and_set_dicts = {}

    # List containing src_zone, dst_zone and rule ID/name for backwards lookup for multiple dst/src/services in a rule
    multi_rule_params = []