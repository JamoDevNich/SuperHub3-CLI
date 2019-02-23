#!/usr/bin/python3

"""
   _____                       _    _       _        _____ _ _            _              _____ _____
  / ____|                     | |  | |     | |      / ____| (_)          | |       /\   |  __ \_   _|
 | (___  _   _ _ __   ___ _ __| |__| |_   _| |__   | |    | |_  ___ _ __ | |_     /  \  | |__) || |
  \___ \| | | | '_ \ / _ \ '__|  __  | | | | '_ \  | |    | | |/ _ \ '_ \| __|   / /\ \ |  ___/ | |
  ____) | |_| | |_) |  __/ |  | |  | | |_| | |_) | | |____| | |  __/ | | | |_   / ____ \| |    _| |_
 |_____/ \__,_| .__/ \___|_|  |_|  |_|\__,_|_.__/   \_____|_|_|\___|_| |_|\__| /_/    \_\_|   |_____|
              | |
              |_|

 SuperHub 3 Client API
 Version 1.0.5
 by Nicholas Elliott

"""

import re
import sys
import json
import socket
import random
import base64
import argparse

version = "1.0.4";                  # The version number of this utility
version_firmware = "9.1.116.608";   # The firmware version this utility was tested on
superhub_username = "admin";        # Username goes here, usually this doesn't require changing
superhub_password = "";             # Password goes here, can be pre-filled or left blank
superhub_cookie_header = "";        # This is where the session cookie is stored, don't modify. A new cookie is generated with each request.
superhub_ip_addr = "192.168.0.1";   # The IP Address of your Superhub
parser = argparse.ArgumentParser(); # Argument parser instance
set_verbose_mode = 1;               # Verbose Modes: 0=Result Only, 1=Normal, 2=Extended, 3=Debug
set_list_mode = 0;                  # List Modes: 0=Normal, 1=None(Deprecated), 2=JSON-Compatible

superhub_guestnet_config = {"ssid": "VM_Guest", "psk": "Ch4ngeP4ssword987Ple4se"}; # Default guest network configuration. Please change the default password.
superhub_nonce = str(random.randint(10000,99999)); # https://github.com/JamoDevNich/ClientsAPI-SuperHub3/wiki/OIDs-Documentation#introduction
superhub_req_ext = "&_n="+superhub_nonce;

parser.add_argument("-p", "--password", help="Provide the password for the SuperHub", metavar="N");
parser.add_argument("-c", "--clients", help="Present client information", action="store_true");
parser.add_argument("-w", "--wlan", help="Toggle the WLAN off [0] or on [1]. Guest WLAN off [2] or on [3]. Toggles both 2.4GHz and 5GHz.", metavar="N");
parser.add_argument("-f", "--format", help="Present output in [j]son or [c]onsole format. Silent mode may be necessary.", metavar="X");
parser.add_argument("-v", "--verbose", help="Enable verbose mode", action="store_true");
parser.add_argument("-r", "--reboot", help="Reboot your SuperHub", action="store_true");
parser.add_argument("-s", "--silent", help="Only output result. Note: Ensure desired operation in normal mode before invoking silent mode", action="store_true");
args = parser.parse_args();

if args.verbose is True and args.silent is True:
	raise Exception("Creativity is that marvelous capacity to grasp mutually distinct realities and draw a spark from their juxtaposition. - Max Ernst");
if args.verbose is True:
	set_verbose_mode = 2;
elif args.silent is True:
	set_verbose_mode = 0;

if args.format is not None:
	if args.format in ["j", "json"]:
		set_list_mode = 2;
	elif args.format in ["c", "console"]:
		set_list_mode = 0;
	else:
		raise Exception("Output format is not valid, see help -h");




def printx(text="",verbosetype=1):
	"""Prints text to the console

	Keyword arguments:
	text -- input text (default empty)
	verbosetype -- verbose level at which text will print (default 1)"""

	if set_verbose_mode >= verbosetype:
		print(text);




def web(addr,customheader="Cache-Control: no-cache"):
	"""Performs a web request and returns result in an array

	Keyword arguments:
	addr -- the address to query
	customheader -- custom header to send (default no-cache)"""

	status = "418";
	svr_furl = addr.split("/",1);
	svr_host = svr_furl[0];
	svr_ureq = "";
	svr_addr = socket.gethostbyname(svr_host);
	response = "";

	if len(svr_furl) > 1:
		svr_ureq = svr_furl[1]; # If a full URI path is available then append it to the GET request

	request_headers_array = ["GET /"+svr_ureq+" HTTP/1.1", "Host: "+svr_host, "Accept: text/html", "User-Agent: python-3.3", "Connection: close", customheader,];
	request_headers_string = "";

	for header in request_headers_array:
		request_headers_string = request_headers_string + header + "\r\n";
	request_headers_string = request_headers_string + "\r\n";
	printx(request_headers_string,3);
	try:
		socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
		socket_instance.connect((svr_addr,80));
		socket_instance.send(request_headers_string.encode());
		responsebuffer = socket_instance.recv(1024);
		while (len(responsebuffer) > 0):
			response += responsebuffer.decode("utf-8");
			responsebuffer = socket_instance.recv(1024);
		socket_instance.close();
		status = "OK"
	except:
		status = "NOTOK"
		printx("--> Socket error, please check connection settings.",2);
	printx(response,3);
	return [status,response];




class Clients:
	""" Manages the retrieval and processing of SuperHub clients """

	def __init__(self):
		""" Constructor """

		self.clients = []; # Stored in the format HOSTNAME - CONN STATUS - IP ADDRESS - MAC ADDRESS
		self.__raw = "";
		self.error = False;


	def fetch(self):
		""" Fetches SuperHub clients """

		clients_list_raw = web(superhub_ip_addr+"/walk?oids=1.3.6.1.4.1.4115.1.20.1.1.2.4.2;"+superhub_req_ext,superhub_cookie_header);
		if clients_list_raw[0] == "NOTOK": # if there was a socket error then return false.
			self.error = True;
		else:
			self.__raw = clients_list_raw[1].split("\r\n\r\n",1)[1]; # return a json formatted string


	def sort(self):
		""" Parses and organises the retrieved list of clients """

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
		self.__raw = re.sub(r",1:Finish", "", self.__raw);
		client_data = self.__raw.split(",");

		""" Place IP addresses and hostnames into a list """
		for item in client_data:
			if item[:len(id_ipaddr_hostname)] == id_ipaddr_hostname:
				temp_storage.append(item);
		for item in temp_storage:
			item = re.sub(id_ipaddr_hostname, "", item);
			devices_all.append(item.split(":"));
		printx("--> "+str(len(temp_storage))+" devices identified",2);
		temp_storage = [];

		""" Place IP addresses and MAC addresses into a list """
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

		""" Place IP addresses and connection status into a list """
		for item in client_data:
			if item[:len(id_ipaddr_connstat)] == id_ipaddr_connstat:
				temp_storage.append(item);
		for item in temp_storage:
			item = re.sub(id_ipaddr_connstat, "", item);
			devices_connected.append(item.split(":"));
		printx("--> "+str(len(temp_storage))+" devices validated",2);
		temp_storage = [];

		""" Merge clients into the self.clients list """
		for item in devices_all:
			for connstatus in devices_connected:
				for macaddrlist in devices_macaddrs:
					if item[0] == connstatus[0] and item[0] == macaddrlist[0]:
						self.clients.append([item[1],connstatus[1],item[0],macaddrlist[1]]);
		printx("--> Matched devices: "+str(len(self.clients))+"/"+str(len(devices_all)),2);
		for item in self.clients:
			if item[1] == "1":
				devices_connected_count += 1;
		printx("--> Connected devices: "+str(devices_connected_count)+"/"+str(len(self.clients)),2);




class WLAN:
	""" Static methods which control the state of the WLAN """

	class Messages:
		""" Messages for the various states and notifications """

		json_output = {"action": "failed"};
		enable = 	"Enabling ";
		disable =	"Disabling ";
		guest =		"Guest ";
		radios =	"WLAN 2.4GHz and 5GHz...";
		radio_off =	"--i Shutting down radios...";
		radio_on =	"--i Powering on radios...";
		timers =	"--i Clearing timers...";
		ssid =		"--i Applying SSIDs...";
		security =	"--i Setting security modes...";
		algorithm =	"--i Configuring WPA algorithm...";
		password =	"--i Configuring password...";
		parental =	"--i Applying restrictions to Guest VWLAN...";
		applying =	"Router is processing changes...";
		success =	"Changes applied successfully!";


	class ErrorMessages:
		""" Messages for the various critical errors which may occur """

		specify_parameter = "--! Please specify 0/1, 2/3 with the wlan parameter.";
		changes_failed =	"--! Changes could not be applied - possibly due to TCP socket error";


	class Oids:
		""" Index of the OIDs used by the WLAN class """

		prefix = "/snmpSet?oid=";
		radio_2400_main = 		"1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10001";
		radio_5000_main = 		"1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10101";
		radio_2400_guest =		"1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10004";
		radio_5000_guest =		"1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10104";
		parental_guest =		"1.3.6.1.4.1.4115.1.20.1.1.2.2.1.39.203";
		timer_2400_guest =		"1.3.6.1.4.1.4115.1.20.1.1.3.22.1.14.10004";
		timer_5000_guest =		"1.3.6.1.4.1.4115.1.20.1.1.3.22.1.14.10104";
		ssid_2400_guest =		"1.3.6.1.4.1.4115.1.20.1.1.3.22.1.2.10004";
		ssid_5000_guest =		"1.3.6.1.4.1.4115.1.20.1.1.3.22.1.2.10104";
		security_2400_guest =	"1.3.6.1.4.1.4115.1.20.1.1.3.22.1.5.10004";
		security_5000_guest =	"1.3.6.1.4.1.4115.1.20.1.1.3.22.1.5.10104";
		algorithm_2400_guest =	"1.3.6.1.4.1.4115.1.20.1.1.3.26.1.1.10004";
		algorithm_5000_guest =	"1.3.6.1.4.1.4115.1.20.1.1.3.26.1.1.10104";
		psk_2400_guest =		"1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2.10004";
		psk_5000_guest =		"1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2.10104";
		apply_changes =			"1.3.6.1.4.1.4115.1.20.1.1.9.0";


	class Control:
		""" Index of the various OID parameters used """

		radio_disable =		"=2;2;";
		radio_enable =		"=1;2;";
		parental_disable =	"=2;2"; # Disable parental controls - NOT VERIFIED
		parental_enable =	"=1;2;";
		timer_default =		"=;4;"; # Research Needed
		security_default =	"=3;2;"; # Research Needed
		algorithm_wpa =		"=2;2;";
		ssid_set_guest =	"="+superhub_guestnet_config["ssid"]+";4;";
		psk_set_guest =		"="+superhub_guestnet_config["psk"]+";4;";
		confirm =			"=1;2;";


	@classmethod
	def radios_disable(cls,radio_2400_name,radio_5000_name):
		""" Manages the disabling of the WLAN radios """

		web(superhub_ip_addr +
			cls.Oids.prefix +
			radio_2400_name +
			cls.Control.radio_disable +
			superhub_req_ext,superhub_cookie_header);
		web(superhub_ip_addr +
			cls.Oids.prefix +
			radio_5000_name +
			cls.Control.radio_disable +
			superhub_req_ext,superhub_cookie_header);


	@classmethod
	def radios_enable(cls,radio_2400_name,radio_5000_name):
		""" Manages the enabling of the WLAN radios """

		web(superhub_ip_addr +
			cls.Oids.prefix +
			radio_2400_name +
			cls.Control.radio_enable +
			superhub_req_ext,superhub_cookie_header);
		web(superhub_ip_addr +
			cls.Oids.prefix +
			radio_5000_name +
			cls.Control.radio_enable +
			superhub_req_ext,superhub_cookie_header);


	@classmethod
	def guest_disable(cls):
		""" Disables the Guest WLAN """

		printx(cls.Messages.radio_off, 2);
		cls.radios_disable(cls.Oids.radio_2400_guest,cls.Oids.radio_5000_guest);

		printx(cls.Messages.timers, 2);
		cls.timer_reset();


	@classmethod
	def guest_enable(cls):
		""" Enables the Guest WLAN """

		printx(cls.Messages.radio_on, 2);
		cls.radios_enable(cls.Oids.radio_2400_guest,cls.Oids.radio_5000_guest);

		printx(cls.Messages.timers, 2);
		cls.timer_reset();

		printx(cls.Messages.ssid, 2);
		web(superhub_ip_addr +
			cls.Oids.prefix +
			cls.Oids.ssid_2400_guest +
			cls.Control.ssid_set_guest +
			superhub_req_ext,superhub_cookie_header);
		web(superhub_ip_addr +
			cls.Oids.prefix +
			cls.Oids.ssid_5000_guest +
			cls.Control.ssid_set_guest +
			superhub_req_ext,superhub_cookie_header);

		printx(cls.Messages.security, 2);
		web(superhub_ip_addr +
			cls.Oids.prefix +
			cls.Oids.security_2400_guest +
			cls.Control.security_default +
			superhub_req_ext,superhub_cookie_header);
		web(superhub_ip_addr +
			cls.Oids.prefix +
			cls.Oids.security_5000_guest +
			cls.Control.security_default +
			superhub_req_ext,superhub_cookie_header);

		printx(cls.Messages.algorithm, 2);
		web(superhub_ip_addr +
			cls.Oids.prefix +
			cls.Oids.algorithm_2400_guest +
			cls.Control.algorithm_wpa +
			superhub_req_ext,superhub_cookie_header);
		web(superhub_ip_addr +
			cls.Oids.prefix +
			cls.Oids.algorithm_5000_guest +
			cls.Control.algorithm_wpa +
			superhub_req_ext,superhub_cookie_header);

		printx(cls.Messages.password, 2);
		web(superhub_ip_addr +
			cls.Oids.prefix +
			cls.Oids.psk_2400_guest +
			cls.Control.psk_set_guest +
			superhub_req_ext,superhub_cookie_header);
		web(superhub_ip_addr +
			cls.Oids.prefix +
			cls.Oids.psk_5000_guest +
			cls.Control.psk_set_guest +
			superhub_req_ext,superhub_cookie_header);

		printx(cls.Messages.parental, 2);
		web(superhub_ip_addr +
			cls.Oids.prefix +
			cls.Oids.parental_guest +
			cls.Control.parental_enable +
			superhub_req_ext,superhub_cookie_header);

		printx("Guest network name: "+superhub_guestnet_config["ssid"]); # TODO: MOVE THESE
		printx("Guest network password: "+superhub_guestnet_config["psk"]);
		cls.Messages.json_output.update(superhub_guestnet_config);


	@classmethod
	def timer_reset(cls):
		""" Resets the WLAN power-on timer """

		web(superhub_ip_addr +
			cls.Oids.prefix +
			cls.Oids.timer_2400_guest +
			cls.Control.timer_default +
			superhub_req_ext,superhub_cookie_header);
		web(superhub_ip_addr +
			cls.Oids.prefix +
			cls.Oids.timer_5000_guest +
			cls.Control.timer_default +
			superhub_req_ext,superhub_cookie_header);


	@classmethod
	def apply_changes(cls):
		""" Applies the WLAN changes requested to the router """

		response_raw = web(superhub_ip_addr +
						cls.Oids.prefix +
						cls.Oids.apply_changes +
						cls.Control.confirm +
						superhub_req_ext,superhub_cookie_header);
		if response_raw[0] == "NOTOK":
			return False;
		else:
			response = json.loads(response_raw[1].split("\r\n\r\n",1)[1]);
			if response[cls.Oids.apply_changes] == "1":
				return True;


	@classmethod
	def operate(cls, function_id):
		""" Handles the enabling and disabling of the WLANs

			Keyword arguments:
			function_id -- wlan configuration to apply
				0 - Disable WLAN
				1 - Enable WLAN
				2 - Disable Guest WLAN
				3 - Enable Guest WLAN"""

		if function_id == "0":
			""" Disable WLAN """

			printx(cls.Messages.disable+cls.Messages.radios);
			cls.radios_disable(cls.Oids.radio_2400_main,cls.Oids.radio_5000_main);

		elif function_id == "1":
			""" Enable WLAN """

			printx(cls.Messages.enable+cls.Messages.radios);
			cls.radios_enable(cls.Oids.radio_2400_main,cls.Oids.radio_5000_main);

		elif function_id == "2":
			""" Disable Guest WLAN """

			printx(cls.Messages.disable+cls.Messages.guest+cls.Messages.radios);
			cls.guest_disable();

		elif function_id == "3":
			""" Enable Guest WLAN """

			printx(cls.Messages.enable+cls.Messages.guest+cls.Messages.radios);
			cls.guest_enable();

		else:
			""" Parameter not recognised """
			printx(cls.ErrorMessages.specify_parameter);
			return None;

		printx(cls.Messages.applying);
		if cls.apply_changes():
			cls.Messages.json_output["action"] = "success";
			if set_list_mode == 2:
				printx(json.dumps(cls.Messages.json_output),0);
			else:
				printx(cls.Messages.success,0);
		else:
			if set_list_mode == 2:
				printx(json.dumps(cls.Messages.json_output),0);
			else:
				printx(cls.ErrorMessages.changes_failed);




class Hub:
	""" Static methods which administer the hub """

	class Messages:
		""" Index of various status messages """

		author =            "SuperHub 3 Client API by Nicholas Elliott";
		version =           "Version "+version;
		searching =         "Searching for "+superhub_ip_addr+"...";
		logging_in =        "Logging in...";
		no_password =       "--! Password not found";
		python_version =    "--! Older version of Python detected, please update to 3.5 or above if you run into issues.";
		enter_password =    "Please enter your SuperHub's passcode: ";
		firmware_check =    "Querying system information...";


	class ErrorMessages:
		""" Index of various exception error messages """

		not_found =         "Could not find SuperHub, please ensure the correct IP address is set";
		login_failed =      "Could not login to SuperHub, password may be incorrect";
		firmware_warn =     "Couldn't check firmware version, something must have went wrong with the login.";

	class Oids:
		""" Index of the OIDs used by the Hub class """

		prefix_set =        "/snmpSet?oid=";
		prefix_get =        "/walk?oids=";
		router_status =     "1.3.6.1.4.1.4115.1.3.4.1.9.2";
		router_hardwrev =   "1.3.6.1.4.1.4115.1.20.1.1.5.10.0";
		router_firmware =   "1.3.6.1.4.1.4115.1.20.1.1.5.11.0";
		router_serial =     "1.3.6.1.4.1.4115.1.20.1.1.5.8.0";
		router_uptime =     "1.3.6.1.2.1.1.3.0";
		reboot_request =    "1.3.6.1.4.1.4115.1.20.1.1.5.15.0";
		reboot_confirm =    "1.3.6.1.2.1.69.1.1.3.0";
		suffix_reboot =     "=2;2;";
		suffix_end =        ";";



	@staticmethod
	def login(hubpass=""):
		"""Authenticates with the hub using a given password, returns Boolean

		Keyword arguments:
		hubpass -- SuperHub password (default empty)"""

		global superhub_cookie_header
		if len(superhub_cookie_header) < 1:
			hublogin_credentials = bytes(base64.b64encode(bytes(superhub_username+":"+hubpass, "UTF-8"))).decode("utf-8");
			hublogin_cookie = web(superhub_ip_addr+"/login?arg="+hublogin_credentials+superhub_req_ext);
			if hublogin_cookie[0] == "NOTOK":
				return False;
			hublogin_cookie = hublogin_cookie[1].split("\r\n\r\n",1)[1]; # separate the header from the page html
			if len(hublogin_cookie) < 1: # If the login has failed i.e. hublogin_cookie variable is empty as hub did not return a response.
				return False;
			superhub_cookie_header = "Cookie: credential="+hublogin_cookie;
		else:
			return True;
		return True;


	@staticmethod
	def logout():
		""" Handles logging out of the hub """

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


	@staticmethod
	def find():
		""" Locates the hub at the IP address specified in superhub_ip_addr """

		html = web(superhub_ip_addr +
					Hub.Oids.prefix_get +
					Hub.Oids.router_status +
					Hub.Oids.suffix_end +
					superhub_req_ext);

		if html[0] == "NOTOK":
			return False;
		html = html[1].split("\r\n\r\n",1)[1];
		try:
			html = json.loads(html);
			if html["1"] == "Finish":
				return True;
		except json.JSONDecodeError: # NOTE: Compatibility with older Python versions <3.5 change this to "ValueError"
			pass;
		return False;


	@staticmethod
	def check_firmware():
		""" Prints various diagnostic information regarding the hub, also warns regarding firmware compatibility """

		diagnostics_index = { Hub.Oids.router_firmware: None,
								Hub.Oids.router_hardwrev: None,
								Hub.Oids.router_uptime: None,
								Hub.Oids.router_serial: None };

		for oid in diagnostics_index:
			session_test = web(superhub_ip_addr +
								Hub.Oids.prefix_get +
								oid +
								Hub.Oids.suffix_end +
								superhub_req_ext,superhub_cookie_header);

			if session_test[0] == "NOTOK": # if there was a socket error then return false.
				return False;
			if session_test[1][:15] != "HTTP/1.1 200 OK":
				printx("--! HTTP/1.1 Response Code "+session_test[1][9:12]+" Received");
				return False;
			diagnostics_index[oid] = json.loads(session_test[1].split("\r\n\r\n",1)[1])[oid];

		if int(re.sub(r"\.", "", diagnostics_index[Hub.Oids.router_firmware])) > int(re.sub(r"\.", "", version_firmware)):
			printx("--! Your SuperHub has updated firmware installed (Version "+diagnostics_index[Hub.Oids.router_firmware]+"), if anything doesn't work please open an issue on GitHub.");

		uptime = ["DDD", "HH", "MM", "SS"];
		uptime_epoch = int(diagnostics_index[Hub.Oids.router_uptime][:len(diagnostics_index[Hub.Oids.router_uptime])-2]);
		uptime[0] = int(uptime_epoch/(60*60*24));   # Days
		uptime[1] = int((uptime_epoch/(60*60))%24); # Hours
		uptime[2] = int((uptime_epoch/60)%60);      # Minutes
		uptime[3] = int(uptime_epoch%60);           # Seconds
		for i in range(0,4):
			uptime[i] = str(uptime[i]);

		printx("--i Firmware "+diagnostics_index[Hub.Oids.router_firmware]+", Hardware revision "+diagnostics_index[Hub.Oids.router_hardwrev]+", Serial "+diagnostics_index[Hub.Oids.router_serial]);
		printx("--i System Uptime: "+uptime[0]+" days "+uptime[1]+"h "+uptime[2]+"m "+uptime[3]+"s");
		return True;


	@staticmethod
	def reboot():
		""" Reboots the hub """

		printx("Rebooting your SuperHub...");
		web(superhub_ip_addr +
			Hub.Oids.prefix_set +
			Hub.Oids.reboot_request +
			Hub.Oids.suffix_end +
			superhub_req_ext,superhub_cookie_header);
		web(superhub_ip_addr +
			Hub.Oids.prefix_set +
			Hub.Oids.reboot_confirm +
			Hub.Oids.suffix_reboot +
			superhub_req_ext,superhub_cookie_header);
		exit(0);


	@staticmethod
	def get_clients():
		""" Returns the clients currently connected to the hub, requires Clients class """

		client_inst = Clients();

		printx("Retrieving clients...");
		client_inst.fetch();
		if client_inst.error:
			raise Exception("The clients could not be retrieved.");
		client_inst.sort();
		if client_inst.error:
			raise Exception("An error occured while sorting the clients.");
		printx();

		if set_list_mode is 2:
			printx(json.dumps(client_inst.clients), 0);
		elif set_list_mode is 0:
			printx(" ===  Connected Clients  === ",0);
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
			pass;


	@staticmethod
	def wlan(arg):
		""" Wrapper for the WLAN.operate method, requires WLAN class """

		WLAN.operate(arg);




class Main:
	""" Core script methods """

	@staticmethod
	def menu():
		""" Main menu for console interface """

		menu_in_loop = True;
		while menu_in_loop:
			printx();
			printx("   wlan 0/1     Toggle Private WLAN off/on");
			printx("   wlan 2/3     Toggle Guest WLAN off/on")
			printx("   clients      List router clients");
			printx("   reboot       Reboot your router");
			printx("   q            Exit program");
			printx();
			command = "";
			while command.split(" ")[0] not in ["wlan", "clients", "reboot", "q"]:
				command = input("Enter a command: ");
				if command.split(" ")[0] == "wlan":
					if len(command.split(" ")) > 1:
						Hub.wlan(command.split(" ")[1]);
					else:
						printx(WLAN.ErrorMessages.specify_parameter);
				elif command == "clients":
					Hub.get_clients();
				elif command == "reboot":
					Hub.reboot();
					menu_in_loop = False;
				elif command == "q":
					menu_in_loop = False;
				else:
					pass;


	@staticmethod
	def app():
		""" Entry point """

		global superhub_cookie_header;
		global superhub_password;

		printx(Hub.Messages.author, 2);
		printx(Hub.Messages.version, 2);
		printx("",2);

		if sys.version_info[0] == 3 and sys.version_info[1] < 5:
			printx(Hub.Messages.python_version);

		printx(Hub.Messages.searching);
		if not Hub.find():
			raise Exception(Hub.ErrorMessages.not_found);

		if len(superhub_password) < 8:
			if (args.password is not None) and len(args.password) > 7:
				superhub_password = args.password;
			else:
				printx(Hub.Messages.no_password, 2);
				while len(superhub_password) < 8:
					superhub_password = input(Hub.Messages.enter_password);

		printx(Hub.Messages.logging_in);
		if not Hub.login(superhub_password):
			raise Exception(Hub.ErrorMessages.login_failed);

		printx(Hub.Messages.firmware_check);
		if not Hub.check_firmware():
			raise Exception(Hub.ErrorMessages.firmware_warn);

		if args.clients is True:
			Hub.get_clients();
		elif args.reboot is True:
			Hub.reboot();
		elif args.wlan is not None: # not None as it takes its own parameters
			Hub.wlan(args.wlan);
		else:
			Main.menu();
		Hub.logout();

Main.app();
