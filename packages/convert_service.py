# Create port list in range 0-65535 at start rather than during loop though each line
port_range = [i for i in range(0, 65536)]

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