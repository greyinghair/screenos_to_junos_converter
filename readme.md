# Intro

This collection of programs is to allow easy bulk conversion form ScreenOS (Netscreeens) to Junos (SRX's).

    git clone git@github.com:greyinghair/screenos_to_junos_converter.git

(Requirements: Python >= 3.6 < 3.8)
(PIP Packages: os, time, re, IPy)
execute:

    pip3 install -r requirements.txt


Put entire firewall config into file, not for partially converting config. 


## What this programme doesn't convert

* NAT (neither MIP's/DIP's/Interface NAT).  (Any policies which include NAT config: source NAT, destination NAT & DIP rules will be created minus the NAT config.
Firewall rules with MIP as destination will NOT be created at all.)
* Interfaces
* VPNs
* Routes

_The Netscreen config needs to be gone through manually for any rules with "dip", "nat" or "MIP" in them to create relevant NAT policies in Junos._

# Scope

Config which is converted from ScreenOS format to JunOS:

* Services/Applications
* Addresses
* Address Groups
* Rules


# Guide

Put config to convert into "netscreen_config.txt" then run the python script:
python3 ./convert.py

There should be 2 files output to same directory as the convert.py script resides in.  Date and time (from when script 
was started) is then appended to each filename:

    1) The converted config ready to copy and paste in bulk to SRX.
    2) NOT converted config file will be the lines of config that were NOT converted to JunOS.
    
Converted rules are named the same as the current Netscreen policy ID's so manually inspect a few rule conversions
to verify they were converted correctly.

Lookups are not performed nor are sanity checks against zone naming.  It is prsumed zone naming remains the same across both ScreenOS and JunOS systems, 
except for the zone named "Management", which is reserved in Junos so if that name exists as a zone in ScreenOS config it will be changed
to "System-Management" for JunOS.

Converted rules are named the same as the current Netscreen policy ID's so manually inspect a few rule conversions
to verify they were converted correctly.

Lookups are not performed nor are sanity checks against zone naming.  It is prsumed zone naming remains the same across both ScreenOS and JunOS systems, 
except for the zone named "Management", which is reserved in Junos so if that name exists as a zone in ScreenOS config it will be changed
to "System-Management" for JunOS.
