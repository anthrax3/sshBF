
# Basic SSH Dictionary Attack
A simple script that uses SSH to attempt to authenticate to a given target.

# Usage

> python ssh_bruteforce.py [OPTIONS] <target>
[OPTIONS]
    -h  This help menu
    -u  Specify a filepath with a list of usernames to try -- one username per line
    -p  Specify a filepath with a list of passwords to try -- one password per line
    -t  Set the time between requests (in seconds)
    
Ex:

> python ssh_bruteforce.py -u /usr/share/ncrack/default.usr -p /usr/share/ncrack/default.pwd 127.0.0.1

# Requirements
Requirements are specified in requirements.txt