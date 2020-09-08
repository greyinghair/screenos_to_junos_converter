# This is a script to convert ScreenOS Services/Objects/Rules to Junos equivalent config
# Will read input from a file to allow bulk conversions and write output to a file

import time  # Time module for calculating runtime of script
import re  # module for regex
from IPy import IP # IP lookups and validation module
from datetime import datetime # Create timestamp for use in filename to make output name unique

start_time = time.time() # Used for overtime time of run

timenow = datetime.now() # Get date and time into variable
timestamp = timenow.strftime(f'%Y%m%d_%H%M%S') # Change to useable variable to append to filenames

# Create port list in range 0-65535 at start rather than during loop though each line
port_range = []
for i in range(0, 65536):
    port_range.append(i)

# Variable to calc and store how many lines in file being used as input
num_lines = sum(1 for line in open('netscreen_config.txt'))

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
        "SSH": "junos-telnet",
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


def combine_dicts(*args):  # This dict combine syntax is ONLY valid in python >= 3.5

    # If "service" passed as argument then combine all service dictionaries and populate empty dir
    if "service" in args:
        master.service_dicts = {**master.default_app, **master.service_ns_to_junos, **master.service_grp_to_app_set}

    # Elif "address" passed as argument then combine all address and address set dictionaries
    elif "address" in args:
        master.address_and_set_dicts = {**master.addresses_ns_to_junos, **master.address_group_ns_to_junos_address_set,
                                        **master.default_addr}


def read_file():  # File to read Netscreen config from (INPUT) and then pass to dedicated functions based on regex

    start_time = time.time() # Used to calc time per line to process

    # Start of new new post cleanup of old files
    input_file = open("netscreen_config.txt", "r")

    # Create missing Junos config
    missing_config = ["set applications application udp_161 protocol udp destination-port 161",
                      "set applications application-set junos-dns application junos-dns-udp",
                      "set applications application-set junos-dns application junos-dns-tcp"]
    for entry in missing_config:
        converted_config_output(entry)


    for linecount, line in enumerate(input_file):

        print(f'Parsing line: {linecount + 1}/{num_lines}')  # Print line number of x being parsed

        # Looks for "set dst-address "something" and nothing else after it, ie for a multi destination address rule:
        if re.search("^set dst-address (\".+\")$", line):
            multi_line_rule(line, f'destination-address')

        # Looks for "set src-address "something" and nothing else after it, ie for a multi source address rule:
        elif re.search("^set src-address (\".+\")$", line):
            multi_line_rule(line, f'source-address')

        # Looks for "set service "<something>" and nothing else after it, ie for multi service rule:
        elif re.search("^set service (\".+\")$", line):
            multi_line_rule(line, f'application')

        # Looks for "set service "" (protocol|+)
        elif re.search("^set service \"\S+\s(protocol|\+)", line):

            # Pass line from file to function for iteration and convert line, return results into variable
            # return 2 values
            junos_app_name, converted_line = convert_service_in_file(line)
            # Find NS service (regex finding 1st instance (index 0) of "something" and put into variable.
            ns_service = re.findall( rf'"([^"]*)"', line )[0]

            if "+" in line:  # After creating service above proceed to create set
                multi_server_app_set(ns_service, junos_app_name)  # Pass NS & Junos names to lookup

            # Create key/value pair for ns -> junos service/app mapping (unless already exists)
            elif ns_service not in master.service_ns_to_junos:  # If entry DO NOT exist
                master.service_ns_to_junos[ns_service] = junos_app_name

            converted_config_output(converted_line)  # Send to function to output service lines to file

            # Combine all 3 service dictionaries into 1 for ease of lookups.  Pass to function to perform action.
            combine_dicts("service")


        # Lookup for "set group service '' add" for creating service groups (app-sets)
        elif re.search("^set group service \"\S+\sadd", line):
            # Send line to below function to process
            create_app_set(line)

        # Match addresses for address book entry conversion
        elif re.search("^set address", line ):
            # Send to address_book function
            create_address_book(line)

        # Match address groups and pass for conversion
        elif re.search("^set group address.+add", line):
            combine_dicts("address") # Combine address and address set dictionaries
            create_address_set(line) # Pass to create address_set

        # Match ruleset
        elif re.search("^set policy id.+\s\S", line):
            create_rule(line)

        else:  # For config not matching above IF conditional (i.e. not expected format)
            junk_file_output(line)  # Pass line that doesn't appear to be a Netscreen service to Junk_file function



    print(f'number of lines converted: {master.succeeded}')
    print(f'number of lines failed and added to junk file: {master.failed}')

    print(f'Runtime - Avg parsing per line of config: --- '
          f'{round((time.time() - start_time) / (master.succeeded + master.failed), 2)} seconds ---')


def converted_config_output(line):  # Write Junos config to (OUTPUT)
    converted = open(f'converted_{timestamp}.txt', "a")
    converted.write(line + "\n")  # Write converted config and newline
    master.succeeded += 1
    converted.close()  # Close file


def junk_file_output(line):  # Write lines not conforming to logic to a junk file for later review
    junk = open(f'not_converted_{timestamp}.txt', "a")
    junk.write(line)  # Write line to file for later review
    master.failed += 1
    junk.close()  # Close file


def convert_service_in_file(line):  # service to junos app. single line of config from input file post sanity check

    junos_migrated = {}  # dictionary to put protocol, dst-port start & dst-port end into

    # Find protocol used and add to dictionary
    proto = ["tcp", "TCP", "udp", "UDP"]  # list of possible protocols

    # loop through each line to extract relevant information
    for x in range(len(proto)):  # loop through ns line for as many times as there are protocols in the list PROTO
        if (f'protocol {proto[x]}') in line:
            junos_migrated["protocol"] = proto[x].lower()  # create extracted protocol key & value in lowercase

        # Condition accounts for multiple protocol NS service which after object creation
        elif (f'+ {proto[x]}') in line:
            junos_migrated["protocol"] = proto[x].lower()  # create extracted protocol key & value in lowercase

    # Ports
    port_range_start = port_range  # not needed but makes next bit of code easier to read/understand
    port_range_end = port_range  # not needed but makes next bit of code easier to read/understand

    # below 2 x for loops to extract dst port range such as 4370-4370 in below example:
    # set service "UDP/4370" protocol udp src-port 0-65535 dst-port 4370-4370

    for x in port_range:  # Find starting dst port
        if (f'dst-port {port_range_start[x]}') in line:
            junos_migrated["port_start"] = port_range_start[x]  # put key:value pair into dictionary

    for y in port_range:  # Find ending dst port
        if (f'dst-port {junos_migrated["port_start"]}-{port_range_end[y]}') in line:
            junos_migrated["port_end"] = port_range_end[y]  # put key:value pair into dictionary

    # print(junos_migrated)   # DEBUG

    # Form the Junos service config from protocol/port info as extracted above and put into variable
    # set applications application UDP_902 protocol udp destination-port 902
    # set applications application TCP_49152-65535 protocol tcp destination-port 49152-65535

    if junos_migrated["port_start"] == junos_migrated["port_end"]:  # If destination port range is only single port
        junos_service = f'set applications application {junos_migrated["protocol"]}_{junos_migrated["port_start"]} ' \
                        f'protocol {junos_migrated["protocol"]} destination-port {junos_migrated["port_start"]}'

        # Create variable with Junos App name based on protocol and dst port
        junos_app_name = (f'{junos_migrated["protocol"]}_{junos_migrated["port_start"]}')

        # Return values of Junos App name & the converted config line
        return junos_app_name, junos_service

    else:  # If the port range is more than a single more name it using start-end ports
        junos_service = f'set applications application {junos_migrated["protocol"]}_{junos_migrated["port_start"]}-' \
                        f'{junos_migrated["port_end"]} protocol {junos_migrated["protocol"]} destination-port ' \
                        f'{junos_migrated["port_start"]}-{junos_migrated["port_end"]}'

        # Create variable with Junos App name based on protocol and dst port range
        junos_app_name = (f'{junos_migrated["protocol"]}_{junos_migrated["port_start"]}-{junos_migrated["port_end"]}')

        # Return values of Junos App name & the converted config line
        return junos_app_name, junos_service


def multi_server_app_set(ns_service, junos_app_name):  # Create Application SET from service with multiple TCP/UDP or ports

    ## this function is called for NS services that have multiple services and port ranges (small number of)

    # Create name for Application-Set based on sanitised NS service name
    app_set_name = sanity_check_naming(ns_service)

    # Create the Junos config with group name and Junos app/service entry
    converted_line = (f'set applications application-set {app_set_name}_group application {junos_app_name}').lower()

    # Populate dictionary with netscreen multi service name to junos app set name mapping
    master.service_grp_to_app_set[ns_service] = f'{app_set_name}_group'.lower()

    ## Start of multi service + processing
    # Used for the line above the + in services, ie the 1st of the group that is hard to identify
    delete_from_dict = False
    for ns_key, junos_value in master.service_ns_to_junos.items():
        if ns_service in ns_key:
            first_line_of_grp = (f'set applications application-set {app_set_name}_group application '
                                 f'{junos_value}').lower()
            converted_config_output(first_line_of_grp)
            # Only be called if del is true due to conditions
            delete_from_dict = True  # Change value in variable so entry can be deleted

    if delete_from_dict:  # If is true (ie already an entry in dict for this then delete)
        del master.service_ns_to_junos[ns_service]
    ## End of multi service + processing

    # Output primary line to output to file
    converted_config_output(converted_line)


def create_app_set(line): # Convert service groups to application sets
    junos_app_name = ""  # Create empty so can be used in loop and assignment later in this function

    # Match first instance of "<non-whitespace>"
    ns_group_name = re.findall(rf'"([^"]*)"', line)[0]  # Index 0, i.e. first instance of

    # Create Junos Service SET name based on Netscreen name post sanity check for naming syntax
    junos_app_set_name = sanity_check_naming(ns_group_name)

    # Find the junos_app name from the netscreen service name in the dictionary
    # find NS service name in line 1st: in this case anything between 2nd set of ""
    # e.g.  set group service "ms-ad_members_group" add "TCP/636"

    ns_service_member = re.findall(rf'"([^"]*)"', line)[1]  # match between quotes, 2nd set i.e. index 1

    # Search combined service dictionaries
    for x in master.service_dicts:
        if x == ns_service_member:
            # print(service_dicts[x]) # print corresponding Junos mapping
            junos_app_name = master.service_dicts[x]

    # Create the Junos config with group name and Junos app/service entry
    converted_line = (
        f'set applications application-set {junos_app_set_name} application {junos_app_name}'.lower())

    # Populate combined dictionary with netscreen multi service name to junos app set name mapping
    master.service_dicts[ns_group_name] = f'{junos_app_set_name}'.lower()

    # Output primary line to output to service_group file
    converted_config_output(converted_line)


def zone_name(line): # Find zone name and put into dictionary

    # Zone. (Don't store in dictionary.) Match first instance of "<non-whitespace>"
    zone = re.findall( rf'"([^"]*)"', line)[0]  # Index0,i.e. 1st instance of ""
    if zone == "management":
        zone = "System-Management"  # replace management zone name as system-management a reserved zone on SRX's

    if zone not in master.list_of_zones:  # If zone name is NOT already in the zone list then:
        master.list_of_zones.append( zone )  # Append zone name to zone list
    return zone


def create_address_book(original_line): # Address conversion
    # Function to create the address book entries

    # Remove Description from address book lines. delete <whitespace>"anything" if at end of line
    line = re.sub(rf'\s"([^"]*)"$', '', original_line)

    # Extra Zone name
    zone = zone_name(line)

    # Address naming
    ns_address = re.findall(rf'"([^"]*)"', line)[1] # 2nd instance of "something"

    # Sanity check and correct naming and return the value into a variable.
    junos_address_name = sanity_check_naming(ns_address)

    # Populate address dictionary with netscreen name to junos address mapping
    master.addresses_ns_to_junos[ns_address] = junos_address_name

    #print(junos_address_name)      #   DEBUG


    # If IP/Prefix used in address
    intermediate_fqdn_prefix = line.split('\"')[4] # Extracts the FQDN or IP MASK (after 4th iteration of ")
    fqdn_prefix = intermediate_fqdn_prefix.split(' ')[1] # Reduce variable down to FQDN or prefix only

    # Mask Search at end of line (which should only be mask if it matches the below i.e. the mask)
    mask_list = re.findall(r'\d{1,3}(?:\.\d{1,3}){3}$', line)
    mask = ""
    for x in mask_list: # Convert list into string so can be queries below
        mask += x

    if "255" in mask: # verify it is a subnet

        try:
            prefix_cidr = IP(f'{fqdn_prefix}/{mask}', make_net=True)

        # Define syntax of converted line
            converted_line = f'set security zones security-zone {zone} address-book address {junos_address_name} ' \
                         f'{prefix_cidr}'
        # Pass to function to write to file
            converted_config_output(converted_line)

        except ValueError: # For entries with a mask (so an IP) but prefix not formed correctly or whitespace
            junk_file_output( line )

    # Find FQDN in address
    else:
        try:
            IP(fqdn_prefix, make_net=False) # If is an IP will match this and do nothing
        except: # Else, ie a hostname then
            fqdn = fqdn_prefix.rstrip("\n") # Use cache response after whitespace replaced in line for 2nd group of ""
            # Define syntax of converted line
            converted_line = f'set security zones security-zone {zone} address-book address {junos_address_name} ' \
                             f'dns-name {fqdn}'
            # Pass to function to write to file
            converted_config_output(converted_line)


def create_address_set(line): # Address group to address set conversion

    zone = zone_name(line) # Pass to function to extract zone name
    junos_address_set = ""

    ns_address = re.findall( rf'"([^"]*)"', line )[2]  # 3rd instance of "something", NS address name
    junos_address_name = "" # Empty string to populate in below for loop

    ns_address_grp = re.findall(rf'"([^"]*)"', line)[1]  # 2nd instance of "something", NS address group name

    # Create variable for Junos SET name after sanity check for naming syntax using Netscreen group name
    junos_address_set = sanity_check_naming(ns_address_grp)

    # Put NS address group (key) and Junos address set (value) into dictionary
    master.address_group_ns_to_junos_address_set[ns_address_grp] = junos_address_set

    # Search Address dictionaries
    for x in master.address_and_set_dicts:
        if x == ns_address: # If NS address is found as KEY
            #print(master.address_and_sets[x]) # print corresponding Junos mapping  # DEBUG
            junos_address_name = master.address_and_set_dicts[x]

    # If nesting address-set in address-set then syntax of Junos is diff:
    if junos_address_name in master.address_group_ns_to_junos_address_set:
        converted_line = f'set security zones security-zone {zone} address-book address-set {junos_address_set} ' \
                           f'address-set {junos_address_name}'

    # If member of address set is an address then use below syntax fort junos config:
    else:
        converted_line = f'set security zones security-zone {zone} address-book address-set {junos_address_set} ' \
                         f'address {junos_address_name}'

    # Pass to function to write to file
    converted_config_output(converted_line)


def create_rule(line): # Rule conversion
    try:

        # Remove 'name "something" ' from the line.  Fewer matches as possible (lazy quantifier ?)
        # so zone name lookups works, so 1st "something" is now always Src Zone.
        line = re.sub( rf'(name\s\"(.+?)\"\s)', '', line)

        # Don't convert disabled or ALG IGNORE lines such as 'set policy id 26145 application "IGNORE"'
            # i.e. if NOT 'set policy id <num> from' then don't process further
        if not re.search("^set policy id \d+ from", line ):
            junk_file_output(line) # Write to not_converted file and don't process further
            #print(f'junked line {line}')

        else:

            src_zone = zone_name(re.findall(rf'(\"\S+\")', line)[0])  # 1st instance of "<something>" and pass to
            # zone_name

            dst_zone = zone_name(re.findall(rf'(\"\S+\")', line)[1])  # 2nd instance of "<something>" and pass to
            # zone_name

            policy_id = re.findall(rf'(\d+)', line)[0]  # Policy ID which is 1st instance of
            # whitespace<numbers>whitespace

            ## Place into master class list for lookups for multi src/dst/services rules
            master.multi_rule_params = [src_zone, dst_zone, policy_id]

            # Get netscreen source address name from line
            ns_src_addr = re.findall(rf'"(\S+)"', line)[2]  # Third instance of "<something>"
            # Perform lookup of name against a Dict to get the Junos address name or group
            src_addr = master.address_and_set_dicts[ns_src_addr]

            # Get netscreen destination address name from line
            ns_dst_addr = re.findall(rf'"(\S+)"', line)[3]  # Fourth instance of "<something>"
            # Perform lookup of name against a Dict to get the Junos address name or group
            dst_addr = master.address_and_set_dicts[ns_dst_addr]

            ns_service = re.findall(rf'"(\S+)"', line)[4]  # Fifth instance of "<something>"
            junos_service = master.service_dicts[ns_service]

            # Look for permit or deny
            action = re.findall(rf'\b(permit|deny)', line)[-1] # last instance of permit or deny

            # Create Junos config
            # List of syntax's to use in rules at end of converted_line variable for the sake of DRY
            rule_params = [f'match source-address {src_addr}',
                           f'match destination-address {dst_addr}',
                           f'match application {junos_service}',
                           f'then {action}']

            # Form each line of the rule using the above list
            for x in rule_params:
                converted_line = f'set security policies from-zone {src_zone} to-zone {dst_zone} policy ' \
                                      f'{policy_id} {x}'
                #print(converted_line)  #   DEBUG converted rule

                # Pass to function to write to file
                converted_config_output(converted_line)

    except:
        junk_file_output(line)


def multi_line_rule(line, type): # Multi src/dst/service rules
    # Function for multi src/dst/services on a particular rule
    # Look for the type of additional rule in the arg passed, which is just a string to split into loops

    argument = re.findall( rf'"([^"]*)"', line)[0] # 1st instance of "<something>" pull out of loop for DRY e.g.
     #set dst-address "www.google.com"
     #set src-address "my-laptop"
     #set service "TCP/8888"

    src_dst_or_service = re.findall(rf'(.+)', type)[0] # 1st instance of '<something>'. ie whether extra address or app

    # To work out whether to use address or service dict lookup based on string passed in type var
    if src_dst_or_service in ("destination-address", "source-address"):
        dict_to_lookup = master.address_and_set_dicts
    else:
        dict_to_lookup = master.service_dicts

    # Define Junos config and try the lookups but don't error if it fails
    try:
        converted_line = f'set security policies from-zone {master.multi_rule_params[0]} to-zone ' \
                         f'{master.multi_rule_params[1]} policy {master.multi_rule_params[2]} match ' \
                         f'{src_dst_or_service} {dict_to_lookup[argument]}'
            #print(converted_line)  #   Uncomment to debug

        # Pass to function to write to file
        converted_config_output(converted_line)

    except: # If lookup fails when building he policy such as against name lookup of "MIP(77.87.179.216)"
        junk_file_output(line)


def sanity_check_naming(name): # Remove invalid characters from a string

    # Set address_name var to same as address but replace anything in invalid_characters with "_" so works with Junos
    invalid_characters = [" ", ".", "/", "\"", "\'", "\\", "!", "?", "[", "]", "{", "}", "|", "(", ")"]
    for chars in invalid_characters:
        name = name.replace(chars, "_").lower()

    # Alpha numeric list for characters that Junos names are allowed to START with
    alpha_num = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9']

    # Only if start (index 0 / 1st character) of name is NOT alphanumeric
    if name[0].lower() not in alpha_num:
        amended_name = "" # Blank var but populated 4 lines down so can be returned to function outside of loop
        # loop to account for name starting with more than 1 non valid character such as ..dan or //dan
        while name[0].lower() not in alpha_num:
            amended_name = name[1:] # Slice from index 1 onwards, ie removal of 1st character
            # print(f'address starting with invalid character = {amended_name}')    #   Debug invalid naming
            name = amended_name # Change name to use the corrected string to stop loop when string starts alphanumeric
        return amended_name

    # Else, return name after earlier check and removal of non valid characters
    else:
        return name


read_file()  # The call to start the run of the functions

# last one is
#print(master.address_and_set_dicts)
#print(master.addresses_ns_to_junos)
#print(master.service_ns_to_junos)
#print(master.service_grp_to_app_set)
#print(master.service_dicts)
#print(master.list_of_zones)
#print(master.addresses_ns_to_junos)
#print(master.address_group_ns_to_junos_address_set)

# Print out time it took to run this script from start to finish
print("Runtime:--- %s seconds ---" % (time.time() - start_time))