This collection of programs is to allow easy bulk conversion form ScreenOS (Netscreeens) to Junos (SRX's).

    git clone ........

(Requirements: Python >= 3.6 < 3.8)
(PIP Packages: os, time, re, IPy)
execute:
    pip3 install -r requirements.txt

Put entire firewall config into file, not for partially converting config. 

This migration does NOT touch NAT, neither MIP's nor DIP's.  That has to be manually reviewed and NAT put
in place after running in ruleset.  The source NAT, destination NAT & DIP rules will be created minus the NAT config.
Firewall rules with MIP as destination will NOT be created at all.  

So Netscreen config needs to be gone through manually for any rules with "dip", "nat" or "MIP" in them. 

Converted rules are named the same as the current Netscreen policy ID's so manually inspect a few rule conversions
to verify they were converted correctly.

Lookups not performed nor sanity check on zone naming, will presume zone naming remains the same throughout migration, 
except for "Management" is reserved in Junos so if that name exists as a zone in netscreen config it  will be changed
to "System-Management".

Put config to convert into "netscreen_config.txt" then run the python script:
python3 ./convert.py

There should be 2 files output to same directory as the convert.py script resides in.  Date and time (from when script 
was started) is then appended to each filename:

    1) The converted config ready to copy and paste in bulk to SRX.
    2) file will be the lines of config that were NOT converted.