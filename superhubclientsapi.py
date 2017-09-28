import re
import socket
import hashlib

# Yarde Superhub Client API (WiFi Doorbell Transponder) by Nicholas Elliott
# Designed for a wifi doorbell project but can be used for other things I guess?

version = "0.1.2";
superhub_password = "00000000"; # unused, haven't had time to look at exactly how their login script works.
superhub_cookie_header = ""; # do not modify. this is where the session cookie is stored. a new one is generated with each request anyway.
superhub_ip_addr = "192.168.0.1"; # the ip addr of your superhub.
connected_devices = []; # stored in the format HOSTNAME - CONN STATUS - IP ADDRESS. DO NOT CONFUSE WITH DEVICES_CONNECTED ETC...

 # To get access to the keys for the superhub login system, you need to perform an ajax login and capture the data sent using your browser's developer tools.
 # the string will look like this: http://192.168.0.1/login?arg=KEY1&_n=KEY2&_=KEY3 where KEY# is each key number.
superhub_key1 = "YWRtaW46MTQ5MTk5Nzg=";
superhub_key2 = "61808";
superhub_key3 = "1506529783091";
superhub_req_ext = "&_n="+superhub_key2+"&_="+superhub_key3; # do not modify, this is attached to the end of each request.

set_verbose_mode = 1; # verbose modes determine how much data is output. 0 - only result, 1 - output normal and result, 2 - output normal, extended, and result, 3 - debug. 1 is default.
set_list_mode = 0; # list modes determine how the data is output. 0 - console inline, 1 - console table (not working yet), 2 - json-compatible string (WARNING: PLEASE DO SUFFICENT TESTING IF INTENDING TO USE PUBLICLY WITH CGI)
# if console output capture is being used, please check the exit code. errors will be sent though standard output, followed by an erroneous exit code.

# superhub data identifiers
# 1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.3.200.1.4. IP address and hostname prefix
# 1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.14.200.1.4. IP address and device connection status

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

# the hubfind function is used to find the hub.
def hubfind():
	superhub_signature = "cf7777b19bde01785c51e0f2e6654e76"; # the md5 signature of the superhub landing page
	html = web(superhub_ip_addr); # make a request to the hub
	if html[0] == "NOTOK": # if there was a socket error then return false.
		return False;
	html = html[1].split("\r\n\r\n",1)[1]; # separate the header from the page html
	if hashlib.md5(html.encode("utf-8")).hexdigest() == superhub_signature: # compare the known hub landing html md5 signature with the recieved one.
		return True;
	return False;

# the hublogin function will complete a login and leave the cookie identifier in the global superhub_cookie_header variable.
def hublogin(hubpass=""):
	global superhub_cookie_header # necessary so this variable can be changed from within this function
	hublogin_cookie = web(superhub_ip_addr+"/login?arg="+superhub_key1+superhub_req_ext);
	if hublogin_cookie[0] == "NOTOK": # if there was a socket error then return false.
		return False;
	hublogin_cookie = hublogin_cookie[1].split("\r\n\r\n",1)[1]; # separate the header from the page html
	superhub_cookie_header = "Cookie: credential="+hublogin_cookie; ###### INTERACTION WITH OUTSIDE VARIABLE
	return True;

# validate that the login attempt was actually successful
def hubsession_prt():
	session_test = web(superhub_ip_addr+"/walk?oids=1.3.6.1.4.1.4115.1.20.1.1.2.2.1.1;"+superhub_req_ext,superhub_cookie_header);
	if session_test[0] == "NOTOK": # if there was a socket error then return false.
		return False;
	if session_test[1][:15] != "HTTP/1.1 200 OK":
		printx("--! HTTP/1.1 Response Code "+session_test[1][9:12]+" Received");
		return False;
	return True;

# get a list of clients connected to the hub and other info about them
def hubclientdata():
	clients_list_raw = web(superhub_ip_addr+"/walk?oids=1.3.6.1.4.1.4115.1.20.1.1.2.4.2;"+superhub_req_ext,superhub_cookie_header);
	if clients_list_raw[0] == "NOTOK": # if there was a socket error then return false.
		return "";
	return clients_list_raw[1].split("\r\n\r\n",1)[1]; # return a json formatted string
	##printx("**WARNING: SIMULATED DATA FOR TESTING!",0);
	##return open("C:/Users/yardefaragunle/Documents/Python/TESTDATA.txt","r").read();

# filter and sort the client data. _prt means this function prints to the screen.
def clientsort_prt(jsonstring):
	global connected_devices;
	id_ipaddr_hostname = "1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.3.200.1.4."; # the prefix for ip address + hostnames
	id_ipaddr_connstat = "1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.14.200.1.4."; # the prefix for ip address + connection status
	client_data = []; # all data retrieved from the hub goes here. each entry is in the superhub's format (prefix + ip address + data)
	temp_storage = []; # temporary storage used for list altering
	devices_all = []; # list containing all ips and hostnames
	devices_connected = []; # list containing all ips and connection status
	devices_connected_count = 0;

	jsonstring = re.sub(r"{|}|\"", "", jsonstring); # strip the separators from the data
	jsonstring = re.sub(r"\n", "", jsonstring); # strip the newline chars. apparently re.sub isn't recommended for this?
	jsonstring = re.sub(r"\r\n", "", jsonstring); # strip the windows-style cr lf
	jsonstring = re.sub(r",1:Finish", "", jsonstring); # get rid of this rubbish at the end of the json string
	client_data = jsonstring.split(",");

	# put the ip addresses and hostnames into their relevant list
	for item in client_data:
		if item[:len(id_ipaddr_hostname)] == id_ipaddr_hostname:
			temp_storage.append(item);
	for item in temp_storage:
		item = re.sub(id_ipaddr_hostname, "", item);
		devices_all.append(item.split(":"));
	printx("--> "+str(len(temp_storage))+" devices identified",2);
	temp_storage = [];

	# put the ip addresses and connection status into their relevant list
	for item in client_data:
		if item[:len(id_ipaddr_connstat)] == id_ipaddr_connstat:
			temp_storage.append(item);
	for item in temp_storage:
		item = re.sub(id_ipaddr_connstat, "", item);
		devices_connected.append(item.split(":"));
	temp_storage = [];

	if len(devices_all) != len(devices_connected): # make sure both datasets have an equal amount of entries
		printx("--! Warning: Your Super Hub has an unequal amount of devices vs connected status.",2);

	# merge data into the connected_devices list
	for item in devices_all:
		for connstatus in devices_connected:
			if item[0] == connstatus[0]:
				connected_devices.append([item[1],connstatus[1],item[0]]); ####### INTERACTION WITH OUTSIDE VARIABLE
	printx("--> Matched devices: "+str(len(connected_devices))+"/"+str(len(devices_all)),2);

	# show how many of the devices are connected out of the detected devices
	for item in connected_devices:
		if item[1] == "1":
			devices_connected_count += 1;
	printx("--> Connected devices: "+str(devices_connected_count)+"/"+str(len(connected_devices)),2);
	return True;

def clientlist_prt(clientlist):
	if set_list_mode == 0: # print console normal output
		printx(" ==  CONNECTED DEVICES  == ",0);
		printx("",0);
		for item in clientlist:
			if item[1] == "1":
				printx("("+item[2]+") "+item[0],0);
		printx("",0);
		printx("",0);
		printx(" ==  DISCONNECTED DEVICES  == ",0);
		printx("",0);
		for item in clientlist:
			if item[1] == "0":
				printx("("+item[2]+") "+item[0],0);
	elif set_list_mode == 1:
		exit(1);
	else:
		clients = str(clientlist);
		clients = re.sub(r"'","\"",clients);
		printx(clients,0); # print json compatible string

def main():
	printx("Yarde Superhub Client API (Part of the Wifi Doorbell Transponder Project) by Nicholas Elliott");
	printx("Version "+version);
	printx();
	printx("Searching for superhub ("+superhub_ip_addr+")...");
	if not hubfind():
		printx("Could not find superhub. Comment out this part of the script to force find.");
		exit(1);
	printx("Logging in...");
	if not hublogin():
		printx("Could not login to superhub.");
		exit(1);
	printx("Validating login...");
	if not hubsession_prt():
		printx("The login could not be validated. Retrying usually fixes this random error.");
		exit(1);
	printx("Retrieving client data... This can take between 20 seconds up to 2 minutes.");
	client_data = hubclientdata();
	if len(client_data) < 1:
		printx("The connected clients could not be retrieved.");
		exit(1);
	printx("Sorting data, please wait...");
	if not clientsort_prt(client_data):
		printx("An error occured while sorting the client list.");
		exit(1);
	printx();
	clientlist_prt(connected_devices);
	exit(0);

main();
