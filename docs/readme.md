# ScreenOS to Junos Converter
This project is a Python script that converts ScreenOS firewall configurations to Junos firewall configurations. It is designed to help network administrators migrate their firewall configurations from ScreenOS to Junos.

## Features
- Converts ScreenOS firewall config to Junos SRX firewall config
- Generates a Junos configuration file that can be imported into a Junos device

The ScreenOS and Junos commands are different, so the script maps the ScreenOS commands to their equivalent Junos commands. For example, a ScreenOS rule that allows traffic from a specific source to a specific destination on a specific service will be converted to a Junos rule with the same attributes. 

In this folder is documentation from Juniper Networks showing both ScreenOS as well as JunOS commands. This documentation should be used as a reference when developing the conversion script to ensure that the correct Junos commands are generated based on the ScreenOS configuration.

    ./screenos # containers docs for ScreenOS commands
    ./junos # containers docs for Junos commands