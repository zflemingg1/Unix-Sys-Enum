# Unix Sys Enum
Python Script to enumerate basic system info and search for common privilege escalation vectors such as world writable files, misconfigurations, clear-text passwords

### Basic Info
This tool was originally designed to help with some of the vulnhub challenges. There are loads of scripts available for this already, but I wanted a more tailored version as opposed to pages of text that you have to sift through. 

Some of the things it will enumerate are as follows;

* Basic system info - kernel, hostname etc
* Networking info - routing table, interfaces etc
* Driver info - drives mounted etc
* Scheduled cron jobs - sometimes can edit these to elevate privs 
* User info - whoami, history etc
* File permisisons - root writeable directories and files etc
* Sensitive log files and passwords

### Setup
To set up the tool simply clone it i.e. git clone. Navigate into that directory and then enter  pip install -r requirements.txt into the command line. This will install the required python modules if not already installed on your system.

### Launching The Program
To use the program simply open up a terminal navigate to the directory and run it with "python 'Unix_Sys_Enum.py'"

### Built With

* Python 2.7.14

### Authors

*** Zach Fleming --> zflemingg1@gmail.com


