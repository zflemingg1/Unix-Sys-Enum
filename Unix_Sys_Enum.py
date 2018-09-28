#!/usr/bin/python
## Script to enumerate basic system info and search for common privilege escalation vectors such as world writable files, misconfigurations, clear-text passwords

from termcolor import colored # needed for colored print
import subprocess


def banner():
	print colored("""\
  _    _       _         _____             ______                       
 | |  | |     (_)       / ____|           |  ____|                      
 | |  | |_ __  ___  __ | (___  _   _ ___  | |__   _ __  _   _ _ __ ___  
 | |  | | '_ \| \ \/ /  \___ \| | | / __| |  __| | '_ \| | | | '_ ` _ \ """,'red',attrs=['bold']),
	print colored("	Designed For Kali Linux",'white')
	print colored("""\
 | |__| | | | | |>  <   ____) | |_| \__ \ | |____| | | | |_| | | | | | | """,'red',attrs=['bold']),
	print colored("	https://github.com/zflemingg1",'white', attrs=['underline'])
	print colored("""\
  \____/|_| |_|_/_/\_\ |_____/ \__, |___/ |______|_| |_|\__,_|_| |_| |_|
                                __/ |                                   
                               |___/ """,'red',attrs=['bold'])
	print colored("\nGathering System Info ... Please Wait ...",'yellow',attrs=['bold'])

def create_dictionaries():
	results=[]
	
	# Dictionary with basic system info
	systemInfo = {"OS":{"cmd":"cat /etc/issue","msg":"Operating System","results":results}, 
			"KERNEL":{"cmd":"cat /proc/version","msg":"Kernel","results":results}, 
			"HOSTNAME":{"cmd":"hostname", "msg":"Hostname", "results":results}
			}


	# Dictionary with networking Info
	networkInfo = {"NETINFO":{"cmd":"/sbin/ifconfig -a", "msg":"Interfaces", "results":results},
			"ROUTE":{"cmd":"route", "msg":"Route", "results":results},
			"NETSTAT":{"cmd":"netstat -antup | grep -v 'TIME_WAIT'", "msg":"Netstat", "results":results}
			}


	# Dictionary with Drive System Info
	driveInfo = {"MOUNT":{"cmd":"mount","msg":"Mount results", "results":results},
			"FSTAB":{"cmd":"cat /etc/fstab 2>/dev/null", "msg":"fstab entries", "results":results}
			}


	# Dictionary with Scheduled Cron Jobs
	cronjobInfo = {"CRON":{"cmd":"ls -la /etc/cron* 2>/dev/null", "msg":"Scheduled cron jobs", "results":results},
			"CRONW": {"cmd":"ls -aRl /etc/cron* 2>/dev/null | awk '$1 ~ /w.$/' 2>/dev/null", "msg":"Writable cron dirs", "results":results}
			}


	# Dictionary with User Info
	userInfo = {"WHOAMI":{"cmd":"whoami", "msg":"Current User", "results":results},
			"ID":{"cmd":"id","msg":"Current User ID", "results":results},
			"ALLUSERS":{"cmd":"cat /etc/passwd", "msg":"All users", "results":results},
			"SUPUSERS":{"cmd":"grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0{print $1}'", "msg":"Super Users Found:", "results":results},
			"HISTORY":{"cmd":"ls -la ~/.*_history; ls -la /root/.*_history 2>/dev/null", "msg":"Root and current user history (depends on privs)", "results":results},
			"ENV":{"cmd":"env 2>/dev/null | grep -v 'LS_COLORS'", "msg":"Environment", "results":results},
			"SUDOERS":{"cmd":"cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null", "msg":"Sudoers (privileged)", "results":results},
			"LOGGEDIN":{"cmd":"w 2>/dev/null", "msg":"Logged in User Activity", "results":results}
			}


	# Dicitonary with file permissions
	file_permissions = {
			"SUID":{"cmd":"find / \( -type f -perm -4000 -o -type f -perm -2000 \) -exec ls -ld '{}' ';' 2>/dev/null | tail -n +1", "msg":"SUID/SGID Files - Possible Priv Escalation", "results":results},
			"WWDIRSROOT":{"cmd":"find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root", "msg":"World Writeable Directories for User/Group 'Root'", "results":results},
			"WWDIRS":{"cmd":"find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root | tail -n +1 --follow", "msg":"World Writeable Directories for Users other than Root", "results":results},
			"WWFILES":{"cmd":"find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null", "msg":"World Writable Files", "results":results}
			}


	# Dictionary with sensitive file info
	pwdFiles = {"LOGPWDS":{"cmd":"find /var/log -name '*.log' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null", "msg":"Logs containing keyword 'password'", "results":results},
			"CONFPWDS":{"cmd":"find /etc -name '*.c*' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null", "msg":"Config files containing keyword 'password'", "results":results},
			"SHADOW":{"cmd":"cat /etc/shadow 2>/dev/null", "msg":"Shadow File (Privileged)", "results":results}
			}


	# Execute commands and populate results
	systemInfo = execCmd(systemInfo)
	networkInfo = execCmd(networkInfo)
	driveInfo = execCmd(driveInfo)
	cronjobInfo = execCmd(cronjobInfo)
	userInfo = execCmd(userInfo)
	file_permissions = execCmd(file_permissions)
	pwdFiles = execCmd(pwdFiles)
	
	
	return systemInfo, networkInfo, driveInfo, cronjobInfo, userInfo, file_permissions, pwdFiles



# loop through dictionary, execute the commands, store the results, return updated dict
def execCmd(cmdDict):
	for item in cmdDict:
		cmd = cmdDict[item]["cmd"]
		try:
			command_output = subprocess.check_output([cmd], stderr=subprocess.PIPE, shell=True)
			results = command_output.split('\n')
			cmdDict[item]["results"]=results
		except Exception as e:
			if "returned non-zero exit status 1" in str(e):
				continue
			else:
				print str(e)
	return cmdDict



# print results for each command
def printResults(cmdDict):
	for item in cmdDict:
		msg = cmdDict[item]["msg"]
		results = cmdDict[item]["results"]
		print colored("   [+] " + msg,'cyan',attrs=['bold'])
		for result in results:
			if result.strip() != "":
				print "   " + result.strip()
		print 
	return



def main():
	
	banner() # print banner
	systemInfo, networkInfo, driveInfo, cronjobInfo, userInfo, file_permissions, pwdFiles = create_dictionaries() # get dictionaries

	# Print Results
	print colored("[*] GETTING BAIC SYSTEM INFO...\n",'yellow',attrs=['bold'])
	printResults(systemInfo)

	print colored("[*] GETTING NETWORK INFO...\n",'yellow',attrs=['bold'])
	printResults(networkInfo)

	print colored("[*] GETTING DRIVE INFO...\n",'yellow',attrs=['bold'])
	printResults(driveInfo)

	print colored("[*] GETTING CRONJOB INFO...\n",'yellow',attrs=['bold'])
	printResults(cronjobInfo)

	print colored("[*] GETTING USER INFO...\n",'yellow',attrs=['bold'])
	printResults(userInfo)

	print colored("[*] GETTING FILE/DIRECTORY PERMISSION INFO...\n",'yellow',attrs=['bold'])
	printResults(file_permissions)

	print colored("[*] GETTING PASSWORD FILES...\n",'yellow',attrs=['bold'])
	printResults(pwdFiles)

main()
