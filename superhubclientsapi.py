import re
import json
import socket
import random
import base64
import argparse

# Yarde Superhub Client API (WiFi Doorbell Transponder) by Nicholas Elliott
# Designed for a wifi doorbell project but can be used for other things I guess?

version = "1.0.2";					# The version number of this utility
version_firmware = "9.1.116.608";	# The firmware version this utility was tested on
superhub_username = "admin";		# Username goes here, usually this doesn't require changing
superhub_password = "";				# Password goes here, can be pre-filled or left blank
superhub_cookie_header = "";		# This is where the session cookie is stored, don't modify. A new cookie is generated with each request.
superhub_ip_addr = "192.168.0.1";	# The IP Address of your Superhub
superhub_guestnet_config = {"ssid": "VM_Guest", "psk": "Ch4ngeP4ssword987Ple4se"}; # The default configuration for the guest network. Please change the default password.
parser = argparse.ArgumentParser();	# Argument parser instance

superhub_nonce = str(random.randint(10000,99999)); # See comment below
superhub_req_ext = "&_n="+superhub_nonce; # Superhub returns a 400 bad request error without a unique number appended to the request. this is possibly related to the session cookie.

# NOTE: The variables below can now be set via the command line options -f, -v or -s. Setting them here will not be overwritten unless a command line option is specified.
set_verbose_mode = 1; # verbose modes determine how much data is output. 0 - only result, 1 - output normal and result, 2 - output normal, extended, and result, 3 - debug. 1 is default.
set_list_mode = 0; # list modes determine how the data is output. 0 - console inline, 1 - no output but result available within clients.clients variable, 2 - json-compatible string (WARNING: PLEASE DO SUFFICENT TESTING IF INTENDING TO USE PUBLICLY WITH CGI)
# if console output capture is being used, please check the exit code. errors will be sent though standard output, followed by an erroneous exit code.

# Argument parser definitions
parser.add_argument("-p", "--password", help="Provide the password for the SuperHub", metavar="N");
parser.add_argument("-c", "--clients", help="Present client information", action="store_true");
parser.add_argument("-w", "--wlan", help="Toggle the WLAN off [0] or on [1]. Guest WLAN off [2] or on [3]. Toggles both 2.4GHz and 5GHz.", metavar="N");
parser.add_argument("-f", "--format", help="Present output in [j]son or [c]onsole format. Work-in-progress", metavar="X");
parser.add_argument("-v", "--verbose", help="Enable verbose mode", action="store_true");
parser.add_argument("-r", "--reboot", help="Reboot your SuperHub", action="store_true");
parser.add_argument("-s", "--silent", help="Only output result. Note: Ensure desired operation in normal mode before invoking silent mode", action="store_true");
args = parser.parse_args();

#parser.add_argument("-v", "--verbosity", help="Verbosity modes: [0] Result Only [1] Normal [2] Extended [3] Debug", metavar="N");
#if args.verbosity is not None: try: args.verbosity = int(args.verbosity); if args.verbosity < 4 and args.verbosity > -1: set_verbose_mode = args.verbosity; except: pass;

# Check verbosity parameters
if args.verbose is True and args.silent is True:
	raise Exception("Creativity is that marvelous capacity to grasp mutually distinct realities and draw a spark from their juxtaposition. - Max Ernst");
if args.verbose is True:
	set_verbose_mode = 2;
elif args.silent is True:
	set_verbose_mode = 0;

# Check format parameters
if args.format is not None:
	if args.format in ["j", "json"]:
		set_list_mode = 2;
	elif args.format in ["c", "console"]:
		set_list_mode = 0;
	else:
		raise Exception("Output format is not valid, see help -h");

# superhub data identifiers
# 1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.3.200.1.4. IP address and hostname prefix
# 1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.14.200.1.4. IP address and device connection status
# 1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.4.200.1.4. IP address and MAC Address

# SECTION: Core functions

def printx(text="",verbosetype=1):
	if set_verbose_mode >= verbosetype:
		print(text);

# the web function is in charge of tcp requests.
def web(addr,customheader="Cache-Control: no-cache"):
	status = "418";
	svr_furl = addr.split("/",1);
	svr_host = svr_furl[0];
	svr_ureq = "";
	svr_addr = socket.gethostbyname(svr_host);

	if len(svr_furl) > 1:
		svr_ureq = svr_furl[1]; # if a uri path is there then put it in the GET request

	request_headers_array = ["GET /"+svr_ureq+" HTTP/1.1", "Host: "+svr_host, "Accept: text/html", "User-Agent: python-3.3", "Connection: close", customheader,];
	request_headers_string = ""; # do not alter pls this gets overwritten

	for header in request_headers_array:
		request_headers_string = request_headers_string + header + "\r\n";
	request_headers_string = request_headers_string + "\r\n"; # this line is in the right place, do not tab it. thx. this ends the header, lighttpd doesn't respond without double carriage return and newline
	printx(request_headers_string,3); # debugging stuff
	try:
		socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
		socket_instance.connect((svr_addr,80));
		socket_instance.send(request_headers_string.encode());
		responsebuffer = socket_instance.recv(1024);
		response = "";
		while (len(responsebuffer) > 0):
			response += responsebuffer.decode("utf-8");
			responsebuffer = socket_instance.recv(1024); # buffer size in bytes
		socket_instance.close();
		status = "OK"
	except:
		status = "NOTOK"
		printx("--> Socket error, please check connection settings.",2);
	printx(response,3); # debugging stuff
	return [status,response];


class hub:
	# the hubfind function is used to find the hub.
	def find():
		html = web(superhub_ip_addr+"/walk?oids=1.3.6.1.4.1.4115.1.3.4.1.9.2;"+superhub_req_ext); # Request the Router Status API, as this does not require a user login to the router
		if html[0] == "NOTOK": # if there was a socket error then return false.
			return False;
		elif json.loads(html[1].split("\r\n\r\n",1)[1])["1"] == "Finish":
			return True;
		else:
			pass;
		return False;

	# the hublogin function will complete a login and leave the cookie identifier in the global superhub_cookie_header variable.
	def login(hubpass=""):
		global superhub_cookie_header # necessary so this variable can be changed from within this function
		if len(superhub_cookie_header) < 1:
			hublogin_credentials = bytes(base64.b64encode(bytes(superhub_username+":"+hubpass, "UTF-8"))).decode("utf-8");
			hublogin_cookie = web(superhub_ip_addr+"/login?arg="+hublogin_credentials+superhub_req_ext);
			if hublogin_cookie[0] == "NOTOK": # if there was a socket error then return false.
				return False;
			hublogin_cookie = hublogin_cookie[1].split("\r\n\r\n",1)[1]; # separate the header from the page html
			if len(hublogin_cookie) < 1: # If the login has failed i.e. hublogin_cookie variable is empty as hub did not return a response.
				return False;
			superhub_cookie_header = "Cookie: credential="+hublogin_cookie; ###### INTERACTION WITH OUTSIDE VARIABLE **NOTE: if hublogin_cookie is empty, the login failed
		else:
			return True;
		return True;

	# check hub firmware version
	def validate():
		session_test = web(superhub_ip_addr+"/walk?oids=1.3.6.1.4.1.4115.1.20.1.1.5.11.0;"+superhub_req_ext,superhub_cookie_header);
		if session_test[0] == "NOTOK": # if there was a socket error then return false.
			return False;
		if session_test[1][:15] != "HTTP/1.1 200 OK": # Lines 138 - 140 may no longer be needed.
			printx("--! HTTP/1.1 Response Code "+session_test[1][9:12]+" Received");
			return False;
		hub_firmware_version = session_test[1].split("\r\n\r\n",1)[1].split("\n")[1].split(":",1)[1][1:][:-2];
		if int(re.sub(r"\.", "", hub_firmware_version)) > int(re.sub(r"\.", "", version_firmware)):
			printx("--! This has not been tested on your SuperHub's firmware version ("+hub_firmware_version+")");
		else:
			printx("--i Firmware "+hub_firmware_version, 2);
		return True;

	def reboot():
		printx("Rebooting your SuperHub...");
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.5.15.0;"+superhub_req_ext,superhub_cookie_header);
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.2.1.69.1.1.3.0=2;2;"+superhub_req_ext,superhub_cookie_header);
		exit(0);

	def logout():
		global superhub_cookie_header;
		if len(superhub_cookie_header) > 0:
			printx("Logging out...");
			request_logout = web(superhub_ip_addr+"/logout?"+superhub_req_ext,superhub_cookie_header);
			if request_logout[0] == "NOTOK":
				printx("--! Couldn't logout. Would you like to try again (Y/N)?");
				retry = input();
				if retry in ["Y", "y"]:
					logout();
			superhub_cookie_header = "";

class clients:
	clients = [];	# Stored in the format HOSTNAME - CONN STATUS - IP ADDRESS - MAC ADDRESS
	__raw = "";
	error = False;

	def fetch(self):
		clients_list_raw = web(superhub_ip_addr+"/walk?oids=1.3.6.1.4.1.4115.1.20.1.1.2.4.2;"+superhub_req_ext,superhub_cookie_header);
		if clients_list_raw[0] == "NOTOK": # if there was a socket error then return false.
			self.error = True;
		else:
			self.__raw = clients_list_raw[1].split("\r\n\r\n",1)[1]; # return a json formatted string

	# filter and sort the client data. _prt means this function prints to the screen.
	def sort(self):
		id_ipaddr_hostname = "1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.3.200.1.4."; # the prefix for ip address + hostnames
		id_ipaddr_connstat = "1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.14.200.1.4."; # the prefix for ip address + connection status
		id_ipaddr_macaddrs = "1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.4.200.1.4."; # the prefix for ip address + mac address
		client_data = []; # all data retrieved from the hub goes here. each entry is in the superhub's format (prefix + ip address + data)
		temp_storage = []; # temporary storage used for list altering
		devices_all = []; # list containing all ips and hostnames
		devices_macaddrs = []; # list containing all ips and mac addresses
		devices_connected = []; # list containing all ips and connection status
		devices_connected_count = 0;

		if not self.__raw[len(self.__raw)-1:len(self.__raw)] == "}": # check if the self.__raw has a closing bracket, sometimes hub will not end the string properly.
			printx("--! Warning: Dataset is not complete. All devices may not be validatable.",2);

		self.__raw = re.sub(r"{|}|\"", "", self.__raw); # strip the separators from the data
		self.__raw = re.sub(r"\n", "", self.__raw); # strip the newline chars. apparently re.sub isn't recommended for this?
		self.__raw = re.sub(r"\r\n", "", self.__raw); # strip the windows-style cr lf
		self.__raw = re.sub(r",1:Finish", "", self.__raw); # get rid of this rubbish at the end of the json string
		client_data = self.__raw.split(",");

		# put the ip addresses and hostnames into their relevant list
		for item in client_data:
			if item[:len(id_ipaddr_hostname)] == id_ipaddr_hostname:
				temp_storage.append(item);
		for item in temp_storage:
			item = re.sub(id_ipaddr_hostname, "", item);
			devices_all.append(item.split(":"));
		printx("--> "+str(len(temp_storage))+" devices identified",2);
		temp_storage = [];

		# put the ip addresses and mac addresses into their relevant list
		for item in client_data:
			if item[:len(id_ipaddr_macaddrs)] == id_ipaddr_macaddrs:
				temp_storage.append(item);
		for item in temp_storage:
			item = re.sub(id_ipaddr_macaddrs, "", item);
			item = re.sub(r"\$","",item); # remove the dollar signs preceeding each MAC address
			temp_storage_local_0 = item.split(":"); # split the list into ipaddr and mac. this has to be done so the mac can be formatted properly
			temp_storage_local_1 = [temp_storage_local_0[1][i:i+2] for i in range(0, 12, 2)]; # split the string into a list containing pairs of 2 chars
			temp_storage_local_0[1] = ":".join(temp_storage_local_1); # join strings with ":" symbol
			devices_macaddrs.append(temp_storage_local_0);
		printx("--> "+str(len(temp_storage))+" mac addresses identified",2);
		temp_storage = [];

		# put the ip addresses and connection status into their relevant list
		for item in client_data:
			if item[:len(id_ipaddr_connstat)] == id_ipaddr_connstat:
				temp_storage.append(item);
		for item in temp_storage:
			item = re.sub(id_ipaddr_connstat, "", item);
			devices_connected.append(item.split(":"));
		printx("--> "+str(len(temp_storage))+" devices validated",2);
		temp_storage = [];

		# merge data into the self.clients list
		for item in devices_all:
			for connstatus in devices_connected:
				for macaddrlist in devices_macaddrs:
					if item[0] == connstatus[0] and item[0] == macaddrlist[0]:
						self.clients.append([item[1],connstatus[1],item[0],macaddrlist[1]]); ####### INTERACTION WITH OUTSIDE VARIABLE
		printx("--> Matched devices: "+str(len(self.clients))+"/"+str(len(devices_all)),2);

		# show how many of the devices are connected out of the detected devices
		for item in self.clients:
			if item[1] == "1":
				devices_connected_count += 1;
		printx("--> Connected devices: "+str(devices_connected_count)+"/"+str(len(self.clients)),2);


def func_clients():
	client_inst = clients();

	printx("Retrieving clients...");
	client_inst.fetch();
	if client_inst.error:
		raise Exception("The clients could not be retrieved.");
	client_inst.sort();
	if client_inst.error:
		raise Exception("An error occured while sorting the clients.");
	printx();

	if set_list_mode is 2:
		printx(json.dumps(client_inst.clients), 0); # Return JSON formatted output
	elif set_list_mode is 0:
		printx(" ===  Connected Clients  === ",0); # Return Console output
		printx("",0);
		for item in client_inst.clients:
			if item[1] == "1":
				printx("("+item[2]+") ("+item[3]+") "+item[0],0);
		printx("",0);
		printx("",0);
		printx(" ===  Disconnected Clients  === ",0);
		printx("",0);
		for item in client_inst.clients:
			if item[1] == "0":
				printx("("+item[2]+") ("+item[3]+") "+item[0],0);
	else:
		pass; # Return no output

def func_wlan(opt):
	# OID Definitions. This in correct execution order.
	# 1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10004=[1-Enable,2-Disable];2; (Enable/Disable Guest Network 2.4GHz)
	# 1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10104=[1-Enable,2-Disable];2; (Enable/Disable Guest Network 5GHz)
	# 1.3.6.1.4.1.4115.1.20.1.1.3.22.1.14.10004=;4; (Research needed) (Set Timer for Guest Network 2.4GHz)
	# 1.3.6.1.4.1.4115.1.20.1.1.3.22.1.14.10104=;4; (Research needed) (Set Timer for Guest Network 5GHz)
	# 1.3.6.1.4.1.4115.1.20.1.1.3.22.1.2.10004=[Encrypted/Plaintext SSID];4; (Set Encrypted/Plaintext SSID for Guest 2.4GHz)
	# 1.3.6.1.4.1.4115.1.20.1.1.3.22.1.2.10104=[Encrypted/Plaintext SSID];4; (Set Encrypted/Plaintext SSID for Guest 5GHz)
	# 1.3.6.1.4.1.4115.1.20.1.1.3.22.1.5.10004=3;2; (Set Security Mode for Guest 2.4GHz)
	# 1.3.6.1.4.1.4115.1.20.1.1.3.22.1.5.10104=3;2; (Set Security Mode for Guest 5GHz)
	# 1.3.6.1.4.1.4115.1.20.1.1.3.26.1.1.10004=2;2; (Set WPA Algorithm for Guest 2.4GHz)
	# 1.3.6.1.4.1.4115.1.20.1.1.3.26.1.1.10104=2;2; (Set WPA Algorithm for Guest 5GHz)
	# 1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2.10004=[Alphanumeric password with both capital and lowercase letters];4; (Set/Get PSK Guest 2.4GHz)
	# 1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2.10104=[Alphanumeric password with both capital and lowercase letters];4; (Set/Get PSK Guest 5GHz)
	# 1.3.6.1.4.1.4115.1.20.1.1.2.2.1.39.203=1;2; (Research Needed) (Enable Parental Controls for Guest LAN)
	#
	# 1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10001=[1-Enable,2-Disable];2; (Enable/Disable Main WLAN 2.4GHz)
	# 1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10101=[1-Enable,2-Disable];2; (Enable/Disable Main WLAN 5GHz)

	str_wlan = " WLAN 2.4GHz and 5GHz..."; # TODO: Implement checking of WLAN name length and password strength
	json_output = {"action": "failed"};

	if opt == "0":
		printx("Disabling"+str_wlan);
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10001=2;2;"+superhub_req_ext,superhub_cookie_header); # Shut down 2.4GHz
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10101=2;2;"+superhub_req_ext,superhub_cookie_header); # Shut down 5GHz
	elif opt == "1":
		printx("Enabling"+str_wlan);
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10001=1;2;"+superhub_req_ext,superhub_cookie_header); # Enable 2.4GHz
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10101=1;2;"+superhub_req_ext,superhub_cookie_header); # Enable 5GHz
	elif opt == "2":
		printx("Disabling Guest"+str_wlan);
		printx("--i Shutting down radios...", 2);
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10004=2;2;"+superhub_req_ext,superhub_cookie_header); # Shut down 2.4GHz
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10104=2;2;"+superhub_req_ext,superhub_cookie_header); # Shut down 5GHz
		printx("--i Clearing timers...", 2);
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.22.1.14.10004=;4;"+superhub_req_ext,superhub_cookie_header); # Deactivate Timer for 2.4GHz
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.22.1.14.10104=;4;"+superhub_req_ext,superhub_cookie_header); # Deactivate Timer for 5GHz
	elif opt == "3":
		printx("Enabling Guest"+str_wlan);
		printx("--i Powering up radios...", 2);
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10004=1;2;"+superhub_req_ext,superhub_cookie_header); # Enable 2.4GHz
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10104=1;2;"+superhub_req_ext,superhub_cookie_header); # Enable 5GHz
		printx("--i Clearing timers...", 2);
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.22.1.14.10004=;4;"+superhub_req_ext,superhub_cookie_header); # Deactivate Timer for 2.4GHz
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.22.1.14.10104=;4;"+superhub_req_ext,superhub_cookie_header); # Deactivate Timer for 5GHz
		printx("--i Applying SSIDs...", 2);
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.22.1.2.10004="+superhub_guestnet_config["ssid"]+";4;"+superhub_req_ext,superhub_cookie_header); # Set SSID for 2.4GHz
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.22.1.2.10104="+superhub_guestnet_config["ssid"]+";4;"+superhub_req_ext,superhub_cookie_header); # Set SSID for 5GHz
		printx("--i Setting security modes...", 2);
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.22.1.5.10004=3;2;"+superhub_req_ext,superhub_cookie_header); # Set secm for 2.4GHz
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.22.1.5.10104=3;2;"+superhub_req_ext,superhub_cookie_header); # Set secm for 5GHz
		printx("--i Configuring WPA Algorithm...", 2);
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.26.1.1.10004=2;2;"+superhub_req_ext,superhub_cookie_header); # Set alg for 2.4GHz
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.26.1.1.10104=2;2;"+superhub_req_ext,superhub_cookie_header); # Set alg for 5GHz
		printx("--i Configuring password...", 2);
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2.10004="+superhub_guestnet_config["psk"]+";4;"+superhub_req_ext,superhub_cookie_header); # Set psk for 2.4GHz
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2.10104="+superhub_guestnet_config["psk"]+";4;"+superhub_req_ext,superhub_cookie_header); # Set psk for 5GHz
		web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.2.2.1.39.203=1;2;"+superhub_req_ext,superhub_cookie_header); # Apply parental controls? The web interface does this...
		printx("Guest network name: "+superhub_guestnet_config["ssid"]);
		printx("Guest network password: "+superhub_guestnet_config["psk"]);
		json_output.update(superhub_guestnet_config);
	else:
		raise Exception("WLAN parameter not understood, see help -h");

	#Apply settings: /snmpGet?oids=1.3.6.1.4.1.4115.1.20.1.1.9.0; THEN /snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.9.0=1;2;
	printx("Router is applying changes...");
	response_raw = web(superhub_ip_addr+"/snmpSet?oid=1.3.6.1.4.1.4115.1.20.1.1.9.0=1;2;"+superhub_req_ext,superhub_cookie_header);
	if response_raw[0] == "NOTOK": # if there was a socket error
		raise Exception("Could not apply WLAN configuration settings due to a TCP socket error");
	else:
		response = json.loads(response_raw[1].split("\r\n\r\n",1)[1]);
		if response["1.3.6.1.4.1.4115.1.20.1.1.9.0"] == "1":
			json_output["action"] = "success";

		# Return output to the user
		if set_list_mode == 2:
			printx(json.dumps(json_output),0);
		else:
			printx("Operation "+json_output["action"]+".",0);

# Main Procedure
def main():
	global superhub_cookie_header;
	global superhub_password;

	printx("SuperHub 3 Client API by Nicholas Elliott");
	printx("Version "+version);
	printx();

	# Find the SuperHub
	printx("Searching for "+superhub_ip_addr+"...");
	if not hub.find():
		raise Exception("Could not find SuperHub, please ensure the correct IP address is set");

	# Check for password before asking user
	if len(superhub_password) < 8:
		if (args.password is not None) and len(args.password) > 7:
			superhub_password = args.password;
		else:
			printx("--! Password not found", 2);
			while len(superhub_password) < 8:
				superhub_password = input("Please enter your SuperHub's passcode: ");

	# Attempt to login to SuperHub
	printx("Logging in...");
	if not hub.login(superhub_password):
		raise Exception("Could not login to SuperHub, password may be incorrect");

	# Check firmware version
	printx("Checking firmware version...");
	if not hub.validate():
		superhub_cookie_header = "";
		raise Exception("Couldn't check firmware version"); # NOTE: check HTTP response from 'logging in' to check if password was bad.

	# Check parameters to determine which function to execute. If no parameters provided then give user a menu
	if args.clients is True:
		func_clients();
	elif args.reboot is True:
		hub.reboot();
	elif args.wlan is not None: # not None as it takes its own parameters
		func_wlan(args.wlan);
	else:
		printx();
		printx("   wlan 0/1     Toggle Private WLAN off/on");
		printx("   wlan 2/3     Toggle Guest WLAN off/on")
		printx("   clients      List router clients");
		printx("   reboot       Reboot your router");
		printx("   q            Exit program");
		printx();
		command = "";
		while command not in ["wlan 0", "wlan 1", "wlan 2", "wlan 3", "clients", "q"]:
			command = input("Enter a command: ");
		if command.split(" ")[0] == "wlan":
			func_wlan(command.split(" ")[1]);
		elif command == "clients":
			func_clients();
		else:
			pass;
	hub.logout();

main();
