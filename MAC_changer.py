import optparse
import netifaces
import re
import subprocess

'''
For Using just write
python3 MAC_changer.py -i eth0 -m <Your MAC addr>
'''

def get_args():
	parser = optparse.OptionParser()
	parser.add_option("-i", "--interface", dest="interface", help="Please get a interface with -i or --interface")
	parser.add_option("-m", "--mac", dest="new_MAC", help="Please get a MAC with -m or --mac")
	(options, args) = parser.parse_args()
	if not options.interface:
		interface_error = "[-] Please get me a interface"
		parser.error(interface_error)
	if not options.new_MAC:
		MAC_error = "[-] Please get me a MAC address"
		parser.error(MAC_error)
	if options.interface not in get_interfaces():
		interface_validate_error = "[-] Please get me true interface"
		parser.error(interface_validate_error)
	if not re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", options.new_MAC):
		MAC_validate_error = "[-] Please get a me true MAC"
		parser.error(MAC_validate_error)
	return options


def get_interfaces():
	return netifaces.interfaces()



def change_MAC(interface, MAC):
	print("[+] MAC is changing")
	subprocess.run(["sudo", "/sbin/ifconfig", interface, "down"], shell=True)
	subprocess.run(["sudo", "/sbin/ifconfig", interface, "hw", "ether", MAC])
	subprocess.run(["sudo", "/sbin/ifconfig", interface, "up"], shell=True)


'''
	last_check(interface, MAC)


def last_check(interface, MAC):
	output = subprocess.check_output(["/sbin/ifconfig", interface])
	recently_MAC = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", output)
	if recently_MAC is MAC:
		print("[+] Changing done")
	else:
		print("[-] Is a problem in changing")
'''


options = get_args()
change_MAC(options.interface, options.new_MAC)
