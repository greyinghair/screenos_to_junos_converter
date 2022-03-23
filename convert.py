# This is a script to convert ScreenOS Services/Objects/Rules to Junos equivalent config
# Will read input from a file to allow bulk conversions and write output to a file

import time  # Time module for calculating runtime of script
import re  # module for regex
from packages import * # Import local packages
from datetime import datetime

timenow = datetime.now() # Get date and time into variable
timestamp = timenow.strftime(f'%Y%m%d_%H%M%S') # Change to useable variable to append to filenames

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

    # List of all converted (rules ONLY, in Junos format), dans temp testing :-) 
    converted_config = []

    # List of policy ID's which are disabled in ScreenOS
    disabled_policy_id = []


def combine_dicts(*args):  # This dict combine syntax is ONLY valid in python >= 3.5

    # If "service" passed as argument then combine all service dictionaries and populate empty dir
    if "service" in args:
        master.service_dicts = {**master.default_app, **master.service_ns_to_junos, **master.service_grp_to_app_set}

    # Elif "address" passed as argument then combine all address and address set dictionaries
    elif "address" in args:
        master.address_and_set_dicts = {**master.addresses_ns_to_junos, **master.address_group_ns_to_junos_address_set,
                                        **master.default_addr}


def convert_config(line):  
    master.converted_config.append(line) # add converted line to list
    master.succeeded += 1  # Increment sucess count


def converted_config_output():  # Write Junos config from list to file
    converted = open(f'converted_{timestamp}.txt', "a")
    for line in master.converted_config:
        converted.write(line + "\n")  # Write converted config and newline
    converted.close()  # Close file


def read_file():  # File to read Netscreen config from (INPUT) and then pass to dedicated functions based on regex

    # Start of new new post cleanup of old files
    input_file = open("netscreen_config.txt", "r")

    # Create missing Junos config
    missing_config = ["set applications application udp_161 protocol udp destination-port 161",
                      "set applications application-set junos-dns application junos-dns-udp",
                      "set applications application-set junos-dns application junos-dns-tcp"]
    
    [convert_config(i) for i in missing_config]  # Passes missing_config to convert_config.

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
        elif re.search("^set service \".+\s(protocol|\+)", line):

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

            convert_config(converted_line)  # Send to function to output service lines to file

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

        # Find Disabled rule
        elif re.search("^set policy id .+\sdisable$", line):
            print(line)
            policy_id = re.findall(rf'(\d+)', line)[0]  # Policy ID which is 1st instance of whitespace<numbers>whitespace
            master.disabled_policy_id.append(policy_id) # Add policy ID to list for later lookup and rmoveal of policy config

        # Match ruleset
        elif re.search("^set policy id.+\s\S", line):
            create_rule(line)

        else:  # For config not matching above IF conditional (i.e. not expected format)
            master.failed += 1 # Increment failed counter


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
            convert_config(first_line_of_grp)
            # Only be called if del is true due to conditions
            delete_from_dict = True  # Change value in variable so entry can be deleted

    if delete_from_dict:  # If is true (ie already an entry in dict for this then delete)
        del master.service_ns_to_junos[ns_service]
    ## End of multi service + processing

    # Output primary line to output to file
    convert_config(converted_line)


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
    convert_config(converted_line)


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
            convert_config(converted_line)

        except ValueError: # For entries with a mask (so an IP) but prefix not formed correctly or whitespace
            master.failed += 1
            #print(line)

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
            convert_config(converted_line)


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
    convert_config(converted_line)


def create_rule(line): # Rule conversion
    try:


        # Remove 'name "something" ' from the line.  Fewer matches as possible (lazy quantifier ?)
        # so zone name lookups works, so 1st "something" is now always Src Zone.
        line = re.sub( rf'(name\s\"(.+?)\"\s)', '', line)

        # Don't convert disabled or ALG IGNORE lines such as 'set policy id 26145 application "IGNORE"'
            # i.e. if NOT 'set policy id <num> from' then don't process further
        if not re.search("^set policy id \d+ from", line ):
            master.failed += 1 # Increment failed counter
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
            ns_src_addr = re.findall(rf'"([^"]*)"', line)[2]  # Third instance of "<something>"
            # Perform lookup of name against a Dict to get the Junos address name or group
            src_addr = master.address_and_set_dicts[ns_src_addr]

            # Get netscreen destination address name from line
            ns_dst_addr = re.findall(rf'"([^"]*)"', line)[3]  # Fourth instance of "<something>"
            # Perform lookup of name against a Dict to get the Junos address name or group
            dst_addr = master.address_and_set_dicts[ns_dst_addr]
            
            ns_service = re.findall(rf'"([^"]*)"', line)[4]  # Fifth instance of "<something>"
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
                convert_config(converted_line)

    except Exception as e:
        # print(line, e)  Debug exception
        master.failed += 1 # Increment failed counter


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
        convert_config(converted_line)

    except: # If lookup fails when building he policy such as against name lookup of "MIP(77.87.179.216)"
        master.failed += 1 # Increment failed counter


def disabled_rule_cleanup():
    # Remove disabled policies and correct counters
    for x in master.disabled_policy_id: # For each disabled policy ID
        regex = re.compile(rf'^set security policies.+policy {x}.+') # Regex
        master.converted_config = [i for i in master.converted_config if not regex.match(i)] # Replace everything in list that is NOT matched in REGEX
        master.succeeded -= 1 # For each entry remove count of succeeded
        master.failed += 1 # For each entry increment count for failed conversion


if __name__ == "__main__":
    start_time = time.time() # Used for overtime time of run
    read_file()  # The call to start the run of the functions   
    disabled_rule_cleanup() # Remove disabled rules config from list (easier to remove once it has been converted to Junos)
    converted_config_output() # Post cleanup, write list to file
    print(f'number of lines converted: {master.succeeded}')
    print(f'number of lines NOT converted: {master.failed}')
    print("Total Runtime:--- %s seconds ---" % (time.time() - start_time)) # Print out time it took to run this script from start to finish

