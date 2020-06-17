#!/usr/bin/python3

import re
import sys
import json
import enum
import urllib.request
import urllib.parse
import random
import base64
from pprint import pformat

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
 Version 2.0.a1
 https://github.com/JamoDevNich

"""


VERSION = "2.0.a1";     # The version number of this utility
RESULT_MODE = 0;        # (Legacy - for compatibility) List Modes: 0=Normal, 2=JSON-Compatible
VERBOSE_MODE = 2;       # (Legacy - for compatibility) Verbose Modes: 0=Warnings Only, 1=Result Only/Headless, 2=Normal, 3=Extra Details, 4=Debug, 7=Trace.
VERBOSE_MODE = 4;  # TODO: FOR DEBUG
SUPERHUB_GUESTNET_CONFIG = {"ssid": "VM_Guest", "psk": "Ch4ngeP4ssword987Ple4se"};  # Default guest network configuration. TODO: This is a legacy feature and will be replaced with user prompt


class Output:
    """Writes data to the console, filtered to the chosen verbose level. Handles user input.

    Usage examples:
    ```python
    consoleOutput = Output(Output.VerboseLevel.INFO)
    consoleOutput.verbose_level
    consoleOutput.verbose_level = Output.VerboseLevel.DEBUG
    consoleOutput.write(Output.VerboseLevel.INFO, "Hello world...")
    user_input = consoleOutput.read("Prompt message")
    ```

    The Output class handles all interaction with the console - writing data at
    the verbose level specified, and reading input data from the user.

    **Note**
    By default, the verbose level is set by a global integer called `VERBOSE_MODE`.
    This can be overriden by specifying a verbose level during instantiation, as
    seen in the above example.

    @param verbose_level: Desired verbose level of type `Output.VerboseLevel`. **Default: Output.VerboseLevel.CHECK_GLOBAL**
    @param prefer_json: Sets the JSON output preference. This may not be honored by all methods in the application. **Default: False**
    @return: self
    """

    class OutputException(Exception):
        """Raised when an output class specific exception occurs, such as attempting to read user input while running in headless mode."""

    class VerboseLevel(enum.Enum):
        """Enum values for verbose levels.

        | Enum         | Value | Description                                                                                            |
        | ------------ | ----- | ------------------------------------------------------------------------------------------------------ |
        | WARN         | 0     | Used for warnings.                                                                                     |
        | RESULT       | 1     | Used for result data. Allows just the resulting data to be returned when running in headless mode.     |
        | INFO         | 2     | Normal operational messages.                                                                           |
        | DETAILS      | 3     | Operational messages providing user-friendly details.                                                  |
        | DEBUG        | 4     | Method parameters and non-critical warnings intended to be handled at a higher level.                  |
        | TRACE        | 7     | Detailed internal information, such as `__repr__()` reported strategically.                            |
        | CHECK_GLOBAL | 100   | Check for the existence of an integer "VERBOSE_MODE" and set its value as the verbose level.           |
        """

        WARN = 0;
        RESULT = 1;
        INFO = 2;
        DETAILS = 3;
        DEBUG = 4;
        TRACE = 7;
        CHECK_GLOBAL = 100;

    def __init__(self, verbose_level=VerboseLevel.CHECK_GLOBAL, prefer_json=False):
        """*See class docstring*."""
        self.verbose_level = verbose_level;
        self.prefer_json = prefer_json;

    def __repr__(self) -> str:
        """Object's internal state as a string."""
        return "<class %s %s>" \
               % (type(self).__qualname__,
                  pformat({"self._verbose_level": self._verbose_level}));

    def write(self, verbose_level: VerboseLevel, message: str) -> None:
        """Write data to the console at a given verbose level.

        Write data to the console at a given verbose level. For example, debug data would
        be printed using `write(Output.VerboseLevel.DEBUG, "A debug message")` and result
        data would be printed using `write(Output.VerboseLevel.RESULT, "A result message")`

        @param verbose_level: The verbose level that this message applies to, of type `Output.VerboseLevel`. **Required**
        @param message: The message to be written to console. **Required**
        """
        if self._verbose_level >= verbose_level.value:
            self._write(message);

    def read(self, message: str) -> str:
        """Present a prompt for user input. Wraps python's `input()`.

        If user input is attempted to be read at a verbose level that is likely to
        be headless (such as `Output.VerboseLevel.RESULT`) an exception will be thrown.

        @param message: Prompt message to be written to console. **Required**
        @return: user input as str
        """
        if self._verbose_level >= self.VerboseLevel.INFO.value:
            return input("%s: " % message);
        else:
            raise self.OutputException("User input was requested while running in headless/limited output mode.");

    def _write(self, message: str) -> None:
        """Write message to the console.

        Wrapper for python's `print()`, intended to be overriden in an unit test.

        @param message: The message to be written to console. **Required**
        """
        print(message);

    @property
    def prefer_json(self) -> bool:
        """Return JSON output preference."""
        return self._prefer_json;

    @prefer_json.setter
    def prefer_json(self, preference: bool):
        """Set the JSON output preference.

        @param preference: Sets the JSON output preference. This may not be honored by all methods in the application. **Required**
        """
        assert type(preference) is bool, "JSON preference must be boolean";
        self._prefer_json = preference;

    @property
    def verbose_level(self) -> int:
        """Retrieve current verbose level as an int."""
        return self._verbose_level;

    @verbose_level.setter
    def verbose_level(self, verbose_level_type: VerboseLevel):
        """Set the verbose level.

        @param verbose_level_type: Desired verbose level, of type `Output.VerboseLevel` **Required**
        """
        assert type(verbose_level_type) is self.VerboseLevel, "Verbose level provided is not of a valid type";
        desired_verbose_level = verbose_level_type.value;

        if verbose_level_type is self.VerboseLevel.CHECK_GLOBAL:
            try:
                desired_verbose_level = int(VERBOSE_MODE);
            except NameError:
                raise NameError("Variable 'VERBOSE_MODE' does not exist. Is it in the global scope?");

        assert desired_verbose_level > 0, "Verbose level must be zero or greater";
        self._verbose_level = desired_verbose_level;


class Utilities:
    """Collection of shared utilities."""

    @staticmethod
    def debug(func: object) -> object:
        """Print method parameters if the verbose level is `Output.VerboseLevel.DEBUG` or greater.

        Usage: decorate a method with `@Utilities.debug`
        """
        def inner(*args, **kwargs) -> object:
            output_instance = None;
            is_object = isinstance(args[0], object);
            class_name = "__main__";
            args_list_raw = list(args);
            args_list_str = [];
            # Search for an instance of 'Output' to use
            output_candidates = [];
            for object_attribute in dir(args[0]):
                # Object Attributes
                output_candidates.append(getattr(args[0], object_attribute))
            for arg in args_list_raw:
                # Arguments
                output_candidates.append(arg);
            for kw in kwargs:
                # Keyword Arguments
                output_candidates.append(kwargs[kw]);
            # Search for an instance of Output among the captured objects
            for candidate in output_candidates:
                if type(candidate) is Output:
                    output_instance = candidate;
                    break;

            # Give up and use defaults if we could not find an 'Output' instance.
            # NOTE: The default 'Output' verbose level will raise NameError if not set up as documented on that method.
            if output_instance is None:
                print("<<< WARNING >>> Instance of '%s' not found. To avoid unintentional behavior, remove the '@%s' decorator from '%s'."
                      % (Output.__qualname__,
                         Utilities.debug.__qualname__,
                         func.__qualname__));
                output_instance = Output();
            # Check if the verbose level is appropriate for logging debug. The minimum is DEBUG.
            if output_instance.verbose_level >= output_instance.VerboseLevel.DEBUG.value:
                if len(args_list_raw) < 1:
                    args_list_raw = list(args);
                # Get class name, if applicable
                if is_object:
                    class_name = type(args_list_raw[0]).__name__;
                    args_list_raw.pop(0);
                # Format each argument
                for item in args_list_raw:
                    args_list_str.append(pformat(item));
                # Format each keyword argument
                for key in kwargs:
                    args_list_str.append("%s=%s"
                                         % (key,
                                            pformat(kwargs[key])));
                # Write all to debug output
                output_instance.write(output_instance.VerboseLevel.DEBUG, "%s %s.%s(%s)"
                                                                          % ("<<< Entering method >>>",
                                                                             class_name,
                                                                             func.__name__,
                                                                             ",".join(args_list_str)));
            return func(*args, **kwargs);
        return inner;

    @staticmethod
    def hex_to_ipv4(hex: str) -> str:
        """Convert a hexadecimal encoded IP address into a decimal dot separated string."""
        if len(hex) < 8:
            return "0.0.0.0";
        else:
            octets = re.findall(r"([0-9A-Fa-f]{2})", hex.replace("$", ""));  # Code from original firmware
            for octet in range(len(octets)):
                octets[octet] = str(int(octets[octet], 16));  # Converting to string, because string.join does not accept integers
            return ".".join(octets);

    @staticmethod
    def ipv4_to_hex(ipv4: str) -> str:
        """Convert a decimal dot separated string to a hexadecimal encoded IP address."""
        ip = ipv4.split(".");
        if len(ip) != 4:
            return "$00000000";
        else:
            for octet in range(len(ip)):
                ip[octet] = str(hex(int(ip[octet]))).replace("0x", "");
                if int(ip[octet], 16) < 10:
                    ip[octet] = "0" + ip[octet];  # Pad with a zero if less than 10
            return "$"+"".join(ip);

    @staticmethod
    def epoch_to_list(epoch: int) -> list:
        """Convert an epoch timestamp into a list containing days, hours, minutes and seconds."""
        dur = ["DDD", "HH", "MM", "SS"];
        dur[0] = int(epoch/(60*60*24));      # Days
        dur[1] = int((epoch/(60*60)) % 24);  # Hours
        dur[2] = int((epoch/60) % 60);       # Minutes
        dur[3] = int(epoch % 60);            # Seconds
        return dur;


class HTTPResponse:
    """Contains the status code, headers and body of a HTTP response.

    Usage examples:
    ```python
    HTTPResponse(200, {"Cookie": "session=123456"}, "<!doctype html>...")
    ```

    @param status_code: HTTP Status code received **Required**
    @param headers: Key-value pair of header:value **Required**
    @param body: Response body content **Required**
    @return: self
    """

    # TODO: REMOVE this decorator after dev.
    @Utilities.debug
    def __init__(self, status_code: int, headers: dict, body: str):
        """*See class docstring*."""
        self.status_code = status_code;
        self.headers = headers;
        self.body = body;


class RouterClientDevice:
    """Contains the hostname, MAC address and IP address of a single network device.

    Usage examples:
    ```python
    RouterClientDevice("esp8266-ProjectorBridge", "FC:F5:C4:11:11:11", "10.0.0.1", is_connected=True)
    ```

    @param hostname: Device hostname **Required**
    @param mac_address: Device MAC address **Required**
    @param ip_address: Device IP address **Required**
    @param is_connected: Connected state of device **Required**
    @return: self
    """

    @Utilities.debug
    def __init__(self, hostname: str, mac_address: str, ip_address: str, is_connected: bool):
        """*See class docstring*."""
        self.hostname = hostname;
        self.mac_address = mac_address;
        self.ip_address = ip_address;
        self.is_connected = is_connected;

    def as_legacy_list(self) -> list:
        """Return the legacy list format."""
        return [self.hostname, int(self.is_connected), self.ip_address, self.mac_address];


class Session:
    """Handles authentication with the VM Super Hub 3, and SNMP-over-HTTP requests.

    Usage examples:
    ```python
    sess = Session(password="69691234")
    sess.ip_address
    sess.username
    sess.username = "admin"
    sess.password
    sess.password = "12346969"
    sess.get_oids_walk()
    sess.router_reachable()
    sess.get_firmware_info()
    sess.sign_in()
    sess.sign_out()
    sess.set_oid()  # TODO
    result = sess.get_oid("1.4.6.7.3")
    result = sess.get_oids(["1.4.6.7.3.1", "1.4.6.7.3.2"])
    ```

    @param password: The administration password provided with your router. **Default: "00000000"**
    @param username: The username to sign in with. **Default: "admin"**
    @param ip_address: The router's IP ip_address. **Default: "192.168.0.1"**
    @param auto_recover_session: Enables transparent recovery of an interrupted session. Logged to log level `DETAILS`. Ceases after three failed attempts. **Default: False**. ***Not Implemented***
    @return: Instance of Session.
    """

    class SessionException(Exception):
        """Base class for custom Session exceptions."""

    class SessionSNMPException(SessionException):
        """Raised when an unrecoverable SNMP error occurs. Such an exception can be caught and the request attempted again."""

    class Oids:
        """Index of the OIDs used by the Session class."""

        router_status = "1.3.6.1.4.1.4115.1.3.4.1.9.2";
        firmware_version = "1.3.6.1.4.1.4115.1.20.1.1.5.11.0";

    @Utilities.debug
    def __init__(self, password="00000000", username="admin", ip_address="192.168.0.1", auto_recover_session=False, output_handler=Output()):
        """*See class docstring*."""
        self._out = output_handler;
        self._is_authenticated = False;                     # Internal boolean indicating whether the current session is authenticated
        self.username = username;                           # Method validates input and sets self._username
        self.password = password;                           # Method validates input and sets self._password
        self._ip_address = ip_address;
        self._auto_recover_session = auto_recover_session;  # TODO: currently not implemented. To be used by set_oid, get_oid and get_oids. Log to DETAILS.
        self._auto_recover_session_retry_limit = 3;         # TODO: currently not implemented. To be used in tandem with above. Log to DETAILS.
        self._nonce = str(random.randint(10000, 99999));    # https://github.com/JamoDevNich/SuperHub3-CLI/wiki/OIDs-Documentation#introduction
        self._cookie_header = None;                         # Stores the session cookie. Considered valid if 'self._is_authenticated=true'
        self._default_encoding = "UTF-8";                   # Base64 encoding and decoding (cookie debug and login credentials)
        self._firmware_version_tested = "9.1.1811.401";     # The firmware version this utility was tested on
        self._initialised = True;

        self._out.write(self._out.VerboseLevel.TRACE, "Session initialised: %s"
                                                      % pformat(self));

    def __del__(self):
        """Actions to perform when there are no more references to this object.

        A sign out is initiated to ensure another user to sign-in to the router. This
        is a safeguard and Python does not guarantee that it will call __del__().
        """
        if "_initialised" in dir(self):
            # 'invoked' does not cause any special behavior, it is just used to assist debugging.
            self.sign_out(invoked=1);

    def __repr__(self) -> str:
        """Object's internal state as a string."""
        pformatted = "";
        if "_initialised" in dir(self):
            pformatted = " " + pformat({"self._out": pformat(self._out),
                                        "self._is_authenticated": pformat(self._is_authenticated),
                                        "self._username": pformat(self._username),
                                        "self._password": pformat(self._password),
                                        "self._ip_address": pformat(self._ip_address),
                                        "self._auto_recover_session": pformat(self._auto_recover_session),
                                        "self._auto_recover_session_retry_limit": pformat(self._auto_recover_session_retry_limit),
                                        "self._nonce": pformat(self._nonce),
                                        "self._cookie_header": pformat(self._cookie_header),
                                        "self._default_encoding": pformat(self._default_encoding),
                                        "self._firmware_version_tested": pformat(self._firmware_version_tested)});
        return "<class %s%s>" \
               % (type(self).__qualname__,
                  pformatted);

    def __str__(self) -> str:
        """User-friendly string representation of the object.

        The router's session data (Base 64 encoded in the Cookie) is returned if the
        user is signed in. Otherwise an empty JSON string is returned.

        @return: str
        """
        if type(self._cookie_header) is dict and "Cookie" in self._cookie_header:
            # Extract the Base64 string from the cookie
            cookie_credential = self._cookie_header["Cookie"].split("=", maxsplit=1)[1];
            # Encode it to Bytes for the base64 object
            cookie_credential_base64_bytes = cookie_credential.encode(self._default_encoding);
            # Decode it to an UTF-8 string
            cookie_credential_decoded = base64.b64decode(cookie_credential_base64_bytes).decode(self._default_encoding);
            return cookie_credential_decoded;
        else:
            return """{}""";

    @property
    def ip_address(self) -> str:
        """Return the target router IP address."""
        try:
            return self._ip_address;
        except AttributeError:
            return "";

    @Utilities.debug
    def _set_credential(self, value: str, username=False):
        """Perform input validation on a given value, and update the username or password.

        @param value: A user-provided value to be validated **Required**
        @param username: A boolean determining whether the value should update the username (if True) or the password (if False) **Default: False**
        """
        credential_type = "username" if username else "password";

        assert not self._is_authenticated, "Current session must be terminated before switching credentials";
        assert type(value) is str, "Argument '%s' must be of type string" % credential_type;
        assert len(value) > 0, "Argument '%s' cannot be empty" % credential_type;

        if username:
            self._username = value;
        else:
            self._password = value;

    @property
    def username(self) -> str:
        """Return the session username."""
        try:
            return self._username;
        except AttributeError:
            return "";

    @username.setter
    def username(self, username: str):
        """Update the session username. This can only done when signed out.

        @param username: Username **Required**
        """
        self._set_credential(username, username=True);

    @property
    def password(self) -> str:
        """Retrieve the session password."""
        try:
            if self._password == "00000000":
                return "";
            else:
                return self._password;
        except AttributeError:
            return "";

    @password.setter
    def password(self, password: str):
        """Update the session password. This can only done when signed out.

        @param password: Password **Required**
        """
        self._set_credential(password);

    @Utilities.debug
    def sign_in(self) -> bool:
        """Authenticate new session using existing username and password combination.

        The username or password can be set with `__init__()`, `Session.username` and `Session.password`.

        @return: True if authenticated, False if not authenticated
        """
        return self._sign_in(self._username, self._password);

    @Utilities.debug
    def _sign_in(self, username: str, password: str) -> bool:
        """Authenticate a new session with a given username or password.

        @param username: Administrator username. **Required**
        @param password: Administrator password. **Required**
        @return: True if authenticated, False if not authenticated
        """
        # Check if we're already authenticated
        if self._is_authenticated:
            self._out.write(self._out.VerboseLevel.DETAILS, "Session is already authenticated, duplicate sign-in stopped");
            return True;

        # Check if a password has been set
        if self._password == "00000000":
            raise self.SessionCredentialsException("Password is not set");
        else:
            # Encode the login username and password
            login_credentials_bytes = bytes("%s:%s" % (username, password), self._default_encoding);
            login_credentials_base64_bytes = base64.b64encode(login_credentials_bytes);
            login_credentials_base64_utf8encoded = bytes(login_credentials_base64_bytes).decode(self._default_encoding);

            # Give these credentials to the router (/login?arg=<login_credentials_encoded>)
            login_response = self._http_request("login", {"arg": login_credentials_base64_utf8encoded});

            # Check if we got a OK/200 status code before continuing
            if login_response.status_code != 200:
                self._out.write(self._out.VerboseLevel.DETAILS, "Login failed, Hub responded status code %s"
                                % login_response.status_code);
                return False;

            # We need a valid response body (which contains the cookie information) so exit here if we do not have one
            if len(login_response.body) < 1:
                self._out.write(self._out.VerboseLevel.DETAILS, "Login failed, Hub responded with empty body");
                return False;

            # Create the credential cookie
            self._cookie_header = {"Cookie": "credential=%s" % login_response.body};
            self._is_authenticated = True;
            return True;

    @Utilities.debug
    def sign_out(self, invoked=0, reinitialise_session=True) -> bool:
        """End the current session. A new session can be started with `sign_in()`."""
        if self._is_authenticated:
            # Call the Hub to sign out
            signout_response = self._http_request("logout");

            if signout_response.status_code == 200:
                self._is_authenticated = False;
                if reinitialise_session:
                    self.__init__(self._password, self._username, self._ip_address, self._auto_recover_session, self._out);
                return True;
            else:
                return False;
        else:
            # Already signed out
            self._out.write(self._out.VerboseLevel.DETAILS, "Duplicate sign-out attempted - already signed out. invoked=%s"
                            % str(invoked));
            return True;

    @Utilities.debug
    def set_oid(self, oid: str, value: object) -> bool:
        """Write to a collection of SNMP Object IDs.

        @param oid: String representation of the target OID. **Required**
        @param value: The value to write to the OID, of type str or int. **Required**
        @return: True on success and False on failure.
        """
        # The last digit may be a datatype indicator. Int appears to be 2, String appears to be 4.
        datatype = "2" if type(value) is int else "4";
        value = "" if value is None else value;
        query_parameter = f"{oid}={value};{datatype};";
        response = self._http_request("snmpSet", {"oid": query_parameter});
        if response.status_code == 200:
            response_deserialised = json.loads(response.body);
        else:
            # TODO: retry request after short delay. If user is not authenticated, then do not retry.
            raise NotImplementedError("HTTP response was %s, no handling implemented yet for this response type" % response.status_code);
        return response_deserialised;

    @Utilities.debug
    def get_oid(self, oid: str) -> object:
        """Query a single SNMP Object ID.

        Queries a single SNMP Object ID from the router. The result is returned in a native type if possible.
        On failure, a Session.SessionSNMPException exception is raised.

        @param oid: Object ID to query.
        @return: object
        """
        return self.get_oids([oid])[oid];

    @Utilities.debug
    def get_oids(self, oids: list) -> object:
        """Query a collection of SNMP Object IDs.

        Queries a collection of SNMP Object IDs from the router. The results are returned in an object.
        On failure, a Session.SessionSNMPException exception is raised.

        @param oids: List of Object IDs to query.
        @return: object {&lt;OID&gt;: &lt;OID Value&gt;}
        """
        assert type(oids) is list, "'oids' parameter is not a list";

        response = self._http_request("snmpGet", {"oids": ";".join(oids)});
        if response.status_code == 200:
            response_deserialised = json.loads(response.body);
        else:
            # TODO: retry request after short delay. If user is not authenticated, then do not retry.
            raise NotImplementedError("HTTP response was %s, no handling implemented yet for this response type" % response.status_code);
        return response_deserialised;

    @Utilities.debug
    def get_oids_walk(self, oids: list, legacy=False) -> object:
        """Walk a collection of SNMP Object IDs.

        Queries a given collection of SNMP Object IDs from the router. The results are returned in an object.
        On failure, a Session.SessionSNMPException exception is raised.

        @param oids: List of Object IDs to walk.
        @param legacy: If True, A string will be returned instead of a dict. **Default: False**
        @return: object {&lt;OID&gt;: &lt;OID Value&gt;}
        """
        assert type(oids) is list, "'oids' parameter is not a list";

        response = self._http_request("walk", {"oids": ";".join(oids)});
        if response.status_code == 200:
            if legacy:
                return response.body;
            response_deserialised = json.loads(response.body);
        else:
            # TODO: retry request after short delay. If user is not authenticated, then do not retry.
            raise NotImplementedError("HTTP response was %s, no handling implemented yet for this response type" % response.status_code);
        return response_deserialised;

    @Utilities.debug
    def router_reachable(self) -> bool:
        """Query the Router Status to ensure the router is reachable. This OID does not require authentication to read.

        @return: bool True if reachable, False if unreachable
        """
        try:
            router_connection_status = self.get_oids_walk([self.Oids.router_status]);
            if "1" in router_connection_status.keys():
                return True;
        except (NotImplementedError, self.SessionSNMPException):
            return False;
        except Exception as e:
            self._out.write(self._out.VerboseLevel.WARN,
                            "Unexpected exception occured checking router status: %s"
                            % e);
        return False;

    @Utilities.debug
    def get_firmware_info(self) -> dict:
        """Query the router for firmware information.

        @return: dict(version_validated: bool, reported_version: str, supported_version: str)
        """
        firmware_version = self.get_oid(self.Oids.firmware_version);
        return dict(version_validated=(True if firmware_version >= self._firmware_version_tested else False),
                    reported_version=firmware_version,
                    supported_version=self._firmware_version_tested);

    @Utilities.debug
    def _http_request(self, path: str, parameters={}) -> HTTPResponse:
        """Query a HTTP URL and return the resulting code, headers and body.

        @param path: Path to send a HTTP request to. FQDN must be ommitted. **Required**
        @param parameters: Dict of GET parameters to send with the request. **Optional**
        @return: HTTPResponse
        """
        # Add nonce to the GET query
        parameters["_n"] = self._nonce;

        # Set headers, such as the cookie containing the login credentials
        headers = {};
        if self._cookie_header is not None and type(self._cookie_header) is dict:
            headers.update(self._cookie_header);

        # Build the URL. These chars are not urlencoded: '/' (default), '=' (base64 login suffix), ';' (oid separator)
        url = "http://%s/%s?%s" % (self._ip_address,
                                   path,
                                   urllib.parse.urlencode(parameters, safe='/=;'));

        self._out.write(self._out.VerboseLevel.DETAILS, "Sending request to: %s"
                                                        % url);

        # Build the request
        request = urllib.request.Request(url,
                                         data=None,
                                         headers=headers,
                                         method="GET");

        # Initialize variables to hold the response data
        response = None;        # For HTTPResponse object returned by urlopen()
        response_code = None;   # For returning the response code
        headers_received = {};  # For returning the response headers
        body = None;            # For returning the response body

        # Send the request and save the response. If there is a HTTP error, grab the response code
        try:
            response = urllib.request.urlopen(request);
        except urllib.error.HTTPError as e:
            response_code = e.code;
            self._out.write(self._out.VerboseLevel.WARN, "Error sending request - %s"
                            % pformat(e));

        # If there was a HTTP error, response will be 'None'
        if response is not None:
            response_code = response.getcode();
            body = str(bytes(response.read()).decode("utf8"));
            for header_tuple in response.getheaders():
                header_name, header_content = *header_tuple, ;
                headers_received[header_name] = header_content;

        return HTTPResponse(response_code, headers_received, body);


class RouterSessionClientBase():
    """Base class containing methods common to classes interacting with the router.

    Usage examples:
    ```python
    class MethodName(RouterSessionClient):
        pass
    ```

    @param session: An object of type `Session`. **Required**
    @param output: An object of type `Output`. **Required**
    @return: Instance of *object*.
    """

    def __init__(self, session: Session, output: Output):
        """*See class docstring*."""
        self._session = session;
        self._output = output;


class RouterClients(RouterSessionClientBase):
    """Retrieves all past and current network clients.

    Usage examples:
    ```python
    rc = RouterClients(<session>, <output>)
    client_list = rc.get_legacy()
    client_dict = rc.get()
    ```

    @param session: An object of type `Session`. **Required**
    @param output: An object of type `Output`. **Required**
    @return: Instance of RouterClients.
    """

    class Oids:
        """Index of the OIDs used by the RouterClients class."""

        clients = "1.3.6.1.4.1.4115.1.20.1.1.2.4.2";

    def _collect(self) -> str:
        """Return the router's SNMP clients object."""
        return self._session.get_oids_walk([self.Oids.clients], legacy=True);

    def _sort(self, clients: dict) -> dict:
        """Sort a dictionary of SNMP clients to a more usable dictionary format.

        PLEASE NOTE: This is a legacy method which will be rewritten. The method `get_legacy()` will continue to return this format after the rewrite.
        """
        id_ipaddr_hostname = "1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.3.200.1.4.";  # the prefix for ip address + hostnames
        id_ipaddr_connstat = "1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.14.200.1.4.";  # the prefix for ip address + connection status
        id_ipaddr_macaddrs = "1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.4.200.1.4.";  # the prefix for ip address + mac address
        client_data = [];  # all data retrieved from the hub goes here. each entry is in the superhub's format (prefix + ip address + data)
        temp_storage = [];  # temporary storage used for list altering
        devices_all = [];  # list containing all ips and hostnames
        devices_macaddrs = [];  # list containing all ips and mac addresses
        devices_connected = [];  # list containing all ips and connection status
        devices_connected_count = 0;
        sorted_client_list = [];  # List containing the sorted client list

        if not clients[len(clients)-1:len(clients)] == "}":  # check if 'clients' has a closing bracket, sometimes hub will not end the string properly.
            self._output.write(self._output.VerboseLevel.WARN, "--! Warning: Dataset is not complete. All devices may not be validatable.");

        clients = re.sub(r"{|}|\"", "", clients);  # strip the separators from the data
        clients = re.sub(r"\n", "", clients);  # strip the newline chars. apparently re.sub isn't recommended for this?
        clients = re.sub(r"\r\n", "", clients);  # strip the windows-style cr lf
        clients = re.sub(r",1:Finish", "", clients);
        client_data = clients.split(",");

        # Place IP addresses and hostnames into a list
        for item in client_data:
            if item[:len(id_ipaddr_hostname)] == id_ipaddr_hostname:
                temp_storage.append(item);
        for item in temp_storage:
            item = re.sub(id_ipaddr_hostname, "", item);
            devices_all.append(item.split(":"));
        self._output.write(self._output.VerboseLevel.INFO, "--> "+str(len(temp_storage))+" devices identified");
        temp_storage = [];

        # Place IP addresses and MAC addresses into a list
        for item in client_data:
            if item[:len(id_ipaddr_macaddrs)] == id_ipaddr_macaddrs:
                temp_storage.append(item);
        for item in temp_storage:
            item = re.sub(id_ipaddr_macaddrs, "", item);
            item = re.sub(r"\$", "", item);  # remove the dollar signs preceeding each MAC address
            temp_storage_local_0 = item.split(":");  # split the list into ipaddr and mac. this has to be done so the mac can be formatted properly
            temp_storage_local_1 = [temp_storage_local_0[1][i:i+2] for i in range(0, 12, 2)];  # split the string into a list containing pairs of 2 chars
            temp_storage_local_0[1] = ":".join(temp_storage_local_1);  # join strings with ":" symbol
            devices_macaddrs.append(temp_storage_local_0);
        self._output.write(self._output.VerboseLevel.DETAILS, "--> "+str(len(temp_storage))+" mac addresses identified");
        temp_storage = [];

        # Place IP addresses and connection status into a list
        for item in client_data:
            if item[:len(id_ipaddr_connstat)] == id_ipaddr_connstat:
                temp_storage.append(item);
        for item in temp_storage:
            item = re.sub(id_ipaddr_connstat, "", item);
            devices_connected.append(item.split(":"));
        self._output.write(self._output.VerboseLevel.DETAILS, "--> "+str(len(temp_storage))+" devices validated");
        temp_storage = [];

        # Merge clients into the sorted_client_list list
        for item in devices_all:
            for connstatus in devices_connected:
                for macaddrlist in devices_macaddrs:
                    if item[0] == connstatus[0] and item[0] == macaddrlist[0]:
                        sorted_client_list.append([item[1], connstatus[1], item[0], macaddrlist[1]]);
        self._output.write(self._output.VerboseLevel.DETAILS, "--> Matched devices: "+str(len(sorted_client_list))+"/"+str(len(devices_all)));
        for item in sorted_client_list:
            if item[1] == "1":
                devices_connected_count += 1;
        self._output.write(self._output.VerboseLevel.DETAILS, "--> Connected devices: "+str(devices_connected_count)+"/"+str(len(sorted_client_list)));
        return sorted_client_list;

    def get_legacy(self) -> list:
        """Retrieve a list of clients from the router. This data format is backwards-compatible with v1.x.x."""
        clients_snmp = self._collect();
        return self._sort(clients_snmp);

    def get(self) -> dict:
        """Retrieve a dict of clients from the router."""
        raise NotImplementedError();


class RouterWLAN(RouterSessionClientBase):
    """Allows control over the router's wireless radios.

    NOTE: This legacy class being entirely rewritten to be more pythonic. It's currently a big mess.

    Usage examples:
    ```python
    pass
    ```

    @param session: An object of type `Session`. **Required**
    @param output: An object of type `Output`. **Required**
    @return: Instance of RouterWLAN.
    """

    class Messages:
        """Messages for the various states and notifications."""

        json_output = {"action": "failed"};
        enable = "Enabling ";
        disable = "Disabling ";
        guest = "Guest ";
        radios = "WLAN 2.4GHz and 5GHz...";
        radio_off = "--i Shutting down radios...";
        radio_on = "--i Powering on radios...";
        timers = "--i Clearing timers...";
        ssid = "--i Applying SSIDs...";
        security = "--i Setting security modes...";
        algorithm = "--i Configuring WPA algorithm...";
        password = "--i Configuring password...";
        parental = "--i Applying restrictions to Guest VWLAN...";
        applying = "Router is processing changes...";
        success = "Changes applied successfully!";

    class ErrorMessages:
        """Messages for the various critical errors which may occur."""

        specify_parameter = "--! Please specify 0/1, 2/3 with the wlan parameter.";
        changes_failed = "--! Changes could not be applied - possibly due to TCP socket error";

    class Oids:
        """Index of the OIDs used by the WLAN class."""

        radio_2400_main = "1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10001";
        radio_5000_main = "1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10101";
        radio_2400_guest = "1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10004";
        radio_5000_guest = "1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3.10104";
        parental_guest = "1.3.6.1.4.1.4115.1.20.1.1.2.2.1.39.203";
        timer_2400_guest = "1.3.6.1.4.1.4115.1.20.1.1.3.22.1.14.10004";
        timer_5000_guest = "1.3.6.1.4.1.4115.1.20.1.1.3.22.1.14.10104";
        ssid_2400_guest = "1.3.6.1.4.1.4115.1.20.1.1.3.22.1.2.10004";
        ssid_5000_guest = "1.3.6.1.4.1.4115.1.20.1.1.3.22.1.2.10104";
        security_2400_guest = "1.3.6.1.4.1.4115.1.20.1.1.3.22.1.5.10004";
        security_5000_guest = "1.3.6.1.4.1.4115.1.20.1.1.3.22.1.5.10104";
        algorithm_2400_guest = "1.3.6.1.4.1.4115.1.20.1.1.3.26.1.1.10004";
        algorithm_5000_guest = "1.3.6.1.4.1.4115.1.20.1.1.3.26.1.1.10104";
        psk_2400_guest = "1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2.10004";
        psk_5000_guest = "1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2.10104";
        apply_changes = "1.3.6.1.4.1.4115.1.20.1.1.9.0";

    class Control:
        """Index of the various OID parameters used."""

        radio_disable = "=2;2;";
        radio_enable = "=1;2;";
        parental_disable = "=2;2";  # Disable parental controls - NOT VERIFIED
        parental_enable = "=1;2;";
        timer_default = "=;4;";  # Research Needed
        security_default = "=3;2;";  # Research Needed
        algorithm_wpa = "=2;2;";
        confirm = "=1;2;";  # TRY 2 as CONFIRM....

    def __init__(self, session: Session, output: Output):
        """*See class docstring*."""
        super().__init__(session, output);
        self._cached_data_is_stale = True;
        self._guest_wlan_ssid = "";
        self._guest_wlan_psk = "";
        self._primary_wlan_ssid = "";
        self._primary_wlan_psk = "";

    def radio_disable(self, radio_name) -> None:
        """Manages the disabling of the WLAN radios."""
        self._session.set_oid(radio_name, 2);

    def radio_enable(self, radio_name) -> None:
        """Manages the enabling of the WLAN radios."""
        self._session.set_oid(radio_name, 1);

    def guest_disable(self) -> None:
        """Disable the Guest WLAN."""
        self._output.write(self._output.VerboseLevel.INFO, self.Messages.radio_off);
        self.radio_disable(self.Oids.radio_2400_guest);
        self.radio_disable(self.Oids.radio_5000_guest);

        self._output.write(self._output.VerboseLevel.INFO, self.Messages.timers);
        self.timer_reset();

    def guest_enable(self) -> None:
        """Enable the Guest WLAN."""
        self._output.write(self._output.VerboseLevel.INFO, self.Messages.radio_on);
        self.radio_enable(self.Oids.radio_2400_guest);
        self.radio_enable(self.Oids.radio_5000_guest);

        self._output.write(self._output.VerboseLevel.INFO, self.Messages.timers);
        self.timer_reset();

        self._output.write(self._output.VerboseLevel.INFO, self.Messages.ssid);
        self._session.set_oid(self.Oids.ssid_2400_guest, SUPERHUB_GUESTNET_CONFIG["ssid"]);
        self._session.set_oid(self.Oids.ssid_5000_guest, SUPERHUB_GUESTNET_CONFIG["ssid"]);

        self._output.write(self._output.VerboseLevel.INFO, self.Messages.security);
        self._session.set_oid(self.Oids.security_2400_guest, 3);
        self._session.set_oid(self.Oids.security_5000_guest, 3);

        self._output.write(self._output.VerboseLevel.INFO, self.Messages.algorithm);
        self._session.set_oid(self.Oids.algorithm_2400_guest, 2);
        self._session.set_oid(self.Oids.algorithm_5000_guest, 2);

        self._output.write(self._output.VerboseLevel.INFO, self.Messages.password);
        self._session.set_oid(self.Oids.psk_2400_guest, SUPERHUB_GUESTNET_CONFIG["psk"]);
        self._session.set_oid(self.Oids.psk_5000_guest, SUPERHUB_GUESTNET_CONFIG["psk"]);

        self._output.write(self._output.VerboseLevel.INFO, self.Messages.parental);
        self._session.set_oid(self.Oids.parental_guest, 2);

        self._output.write(self._output.VerboseLevel.INFO, "Guest network name: "+SUPERHUB_GUESTNET_CONFIG["ssid"]);  # TODO: MOVE THESE
        self._output.write(self._output.VerboseLevel.INFO, "Guest network password: "+SUPERHUB_GUESTNET_CONFIG["psk"]);
        self.Messages.json_output.update(SUPERHUB_GUESTNET_CONFIG);

    def timer_reset(self) -> None:
        """Resets the WLAN power-on timer."""
        self._session.set_oid(self.Oids.timer_2400_guest, None);
        self._session.set_oid(self.Oids.timer_5000_guest, None);

    def apply_changes(self) -> bool:
        """Applies the WLAN changes requested to the router."""
        response = self._session.set_oid(self.Oids.apply_changes, 1);
        if response[self.Oids.apply_changes] == "1":
            return True;
        else:
            return False;

    def operate(self, function_id) -> None:
        """ Handles the enabling and disabling of the WLANs

            Keyword Arguments:
            function_id -- wlan configuration to apply
                0 - Disable WLAN
                1 - Enable WLAN
                2 - Disable Guest WLAN
                3 - Enable Guest WLAN"""

        if function_id == "0":
            """Disable WLAN."""
            self._output.write(self._output.VerboseLevel.INFO, self.Messages.disable+self.Messages.radios);
            self.radio_disable(self.Oids.radio_2400_main);
            self.radio_disable(self.Oids.radio_5000_main);

        elif function_id == "1":
            """Enable WLAN."""
            self._output.write(self._output.VerboseLevel.INFO, self.Messages.enable+self.Messages.radios);
            self.radio_enable(self.Oids.radio_2400_main);
            self.radio_enable(self.Oids.radio_5000_main);

        elif function_id == "2":
            """Disable Guest WLAN."""
            self._output.write(self._output.VerboseLevel.INFO, self.Messages.disable+self.Messages.guest+self.Messages.radios);
            self.guest_disable();

        elif function_id == "3":
            """Enable Guest WLAN."""
            self._output.write(self._output.VerboseLevel.INFO, self.Messages.enable+self.Messages.guest+self.Messages.radios);
            self.guest_enable();

        else:
            """Parameter not recognised."""
            self._output.write(self._output.VerboseLevel.INFO, self.ErrorMessages.specify_parameter);
            return None;

        self._output.write(self._output.VerboseLevel.INFO, self.Messages.applying);
        if self.apply_changes():
            self.Messages.json_output["action"] = "success";
            if self._output.prefer_json:
                self._output.write(self._output.VerboseLevel.INFO, json.dumps(self.Messages.json_output));
            else:
                self._output.write(self._output.VerboseLevel.INFO, self.Messages.success);
        else:
            if self._output.prefer_json:
                self._output.write(self._output.VerboseLevel.INFO, json.dumps(self.Messages.json_output));
            else:
                self._output.write(self._output.VerboseLevel.INFO, self.ErrorMessages.changes_failed);


class RouterReboot(RouterSessionClientBase):
    """Provides ability to request the router to reboot.

    Usage examples:
    ```python
    rr = RouterReboot(<Session>,<Output>)
    rr.request()
    ```

    @param session: An object of type `Session`. **Required**
    @param output: An object of type `Output`. **Required**
    @return: Instance of RouterReboot.
    """

    class Oids:
        """Index of the OIDs used by the RouterReboot class."""

        reboot_request = "1.3.6.1.4.1.4115.1.20.1.1.5.15.0";
        reboot_confirm = "1.3.6.1.2.1.69.1.1.3.0";

    def request(self):
        """Request router to reboot."""
        # NOTE: The reboot API does not seem to care about the 'reboot_request' parameter data, it reboots regardless
        self._session.set_oid(self.Oids.reboot_request, None);
        self._session.set_oid(self.Oids.reboot_confirm, 2);
        pass;


class RouterDiagnostics(RouterSessionClientBase):
    """Query router's WAN connection details and system statistics using an active session.

    Usage examples:
    ```python
    rd = RouterDiagnostics(<Session>, <Output>)
    result_dict = rd.get()
    ```

    @param session: An object of type `Session`. **Required**
    @param output: An object of type `Output`. **Required**
    @return: Instance of RouterDiagnostics.
    """

    class Oids:
        """Index of the OIDs used by the RouterDiagnostics class."""

        hardware_revision = "1.3.6.1.4.1.4115.1.20.1.1.5.10.0";
        firmware_version = "1.3.6.1.4.1.4115.1.20.1.1.5.11.0";
        ip_gateway = "1.3.6.1.4.1.4115.1.20.1.1.1.7.1.6.1";  # Hex Format, use Utilities.hex_to_ipv4()
        ip_wan = "1.3.6.1.4.1.4115.1.20.1.1.1.7.1.3.1";  # Hex Format, use Utilities.hex_to_ipv4()
        ip_dns_1 = "1.3.6.1.4.1.4115.1.20.1.1.1.11.2.1.3.1";  # Hex Format, use Utilities.hex_to_ipv4()
        ip_dns_2 = "1.3.6.1.4.1.4115.1.20.1.1.1.11.2.1.3.2";  # Hex Format, use Utilities.hex_to_ipv4()
        ip_lease_remaining = "1.3.6.1.4.1.4115.1.20.1.1.1.12.3.0";  # in seconds
        serial = "1.3.6.1.4.1.4115.1.20.1.1.5.8.0";
        uptime = "1.3.6.1.2.1.1.3.0";  # in seconds, last two digits require truncating

    def get(self) -> dict:
        """Return a dict containing WAN connection details and router statistics."""
        response = self._session.get_oids([self.Oids.firmware_version,
                                           self.Oids.hardware_revision,
                                           self.Oids.uptime,
                                           self.Oids.serial,
                                           self.Oids.ip_wan,
                                           self.Oids.ip_dns_1,
                                           self.Oids.ip_dns_2,
                                           self.Oids.ip_gateway,
                                           self.Oids.ip_lease_remaining]);
        return response;


class CommandLineInterface:
    """Command line interface to interact with the library."""

    class Messages:
        """Index of various status messages."""

        author = "SuperHub 3 Client API by JamoDevNich <github@nich.dev>";
        version_s = "Version %s";
        searching_s = "Searching for %s...";
        signing_in = "Signing in...";
        signing_out = "Signing out...";
        password_not_provided = "--! Password not found";
        password_set_session = "--i Password already set in session";
        password_set_cli = "--i Password set in CLI";
        python_version = "--! Older version of Python detected, please update to 3.5 or above if you run into issues.";
        enter_password = "Please enter your router's passcode";
        firmware_check = "Checking firmware compatibility...";
        firmware_check_report_s = "--! Your SuperHub has updated firmware installed (Version %s), if anything doesn't work please open an issue on GitHub.";
        module_arguments_missing_s = "--! The %s module requires additional arguments. Examples are available in the documentation/wiki on GitHub.";

    class ErrorMessages:
        """Index of various exception error messages."""

        not_found = "Could not find router, please ensure the correct IP address is set.";
        sign_in_failed = "Could not sign in to router, password may be incorrect";
        sign_out_failed = "Could not sign out of router, please use the cookie information below to force a sign out manually";

    class Wrappers:
        """Command-line wrappers for each API method."""

        @staticmethod
        def router_diagnostics(session: Session, output: Output):
            """Print detailed status information retreived from the router."""
            rd = RouterDiagnostics(session, output).get();

            # Trim last two characters from timestamp and pass it to the epoch converter
            uptime = Utilities.epoch_to_list(int(rd[RouterDiagnostics.Oids.uptime][:len(rd[RouterDiagnostics.Oids.uptime])-2]));
            for i in range(0, 4):
                uptime[i] = str(uptime[i]);

            # Pass lease remaining timestamp to epoch converter
            lease_time_remaining = Utilities.epoch_to_list(int(rd[RouterDiagnostics.Oids.ip_lease_remaining]));
            for i in range(0, 4):
                lease_time_remaining[i] = str(lease_time_remaining[i]);

            # Convert the hex values to readable text
            rd[RouterDiagnostics.Oids.ip_wan] = Utilities.hex_to_ipv4(rd[RouterDiagnostics.Oids.ip_wan]);
            rd[RouterDiagnostics.Oids.ip_dns_1] = Utilities.hex_to_ipv4(rd[RouterDiagnostics.Oids.ip_dns_1]);
            rd[RouterDiagnostics.Oids.ip_dns_2] = Utilities.hex_to_ipv4(rd[RouterDiagnostics.Oids.ip_dns_2]);
            rd[RouterDiagnostics.Oids.ip_gateway] = Utilities.hex_to_ipv4(rd[RouterDiagnostics.Oids.ip_gateway]);

            # Return the legacy JSON format
            if output.prefer_json:
                rd_withkeys = {"firmware": rd[RouterDiagnostics.Oids.firmware_version],
                               "hardware": rd[RouterDiagnostics.Oids.hardware_revision],
                               "uptime": rd[RouterDiagnostics.Oids.uptime],
                               "serial": rd[RouterDiagnostics.Oids.serial],
                               "ip": {
                                   "lease_remaining": rd[RouterDiagnostics.Oids.ip_lease_remaining],
                                   "wan": rd[RouterDiagnostics.Oids.ip_wan],
                                   "dns1": rd[RouterDiagnostics.Oids.ip_dns_1],
                                   "dns2": rd[RouterDiagnostics.Oids.ip_dns_2],
                                   "gateway": rd[RouterDiagnostics.Oids.ip_gateway]}};
                output.write(output.VerboseLevel.RESULT, json.dumps(rd_withkeys));

            # Else, return the legacy formatted output
            else:
                formatted_output = "\n";
                formatted_output += "== System ==\n";
                formatted_output += "Serial: " + rd[RouterDiagnostics.Oids.serial] + "\n";
                formatted_output += "Hardware Revision: " + rd[RouterDiagnostics.Oids.hardware_revision] + "\n";
                formatted_output += "Uptime: "+uptime[0]+" days "+uptime[1]+"h "+uptime[2]+"m "+uptime[3]+"s\n\n";
                formatted_output += "== Software ==\n";
                formatted_output += "Firmware: " + rd[RouterDiagnostics.Oids.firmware_version] + "\n\n";
                formatted_output += "== IP Address ==\n";
                formatted_output += "Wan IP: " + rd[RouterDiagnostics.Oids.ip_wan] + "\n";
                formatted_output += "DHCP lease expires in: "+lease_time_remaining[0]+" days "+lease_time_remaining[1]+"h "+lease_time_remaining[2]+"m "+lease_time_remaining[3]+"s\n\n";
                formatted_output += "== Network ==\n";
                formatted_output += "DNS 1: " + rd[RouterDiagnostics.Oids.ip_dns_1] + "\n";
                formatted_output += "DNS 2: " + rd[RouterDiagnostics.Oids.ip_dns_2] + "\n";
                formatted_output += "Gateway: " + rd[RouterDiagnostics.Oids.ip_gateway] + "\n";
                output.write(output.VerboseLevel.RESULT, formatted_output);

        @staticmethod
        def router_reboot(session: Session, output: Output):
            """Request the router to reboot."""
            output.write(output.VerboseLevel.INFO, "Rebooting your router...");
            rr = RouterReboot(session, output);
            rr.request();
            exit(0);

        @staticmethod
        def router_clients(session: Session, output: Output):
            """Print the clients currently connected to the router."""
            rc = RouterClients(session, output);

            output.write(output.VerboseLevel.INFO, "Retrieving clients...");
            clients_list = rc.get_legacy();

            if output.prefer_json:
                output.write(output.VerboseLevel.RESULT, json.dumps(clients_list));

            else:
                output.write(output.VerboseLevel.RESULT, " ===  Connected Clients  === ");
                output.write(output.VerboseLevel.RESULT, "");
                for endpoint in clients_list:
                    if endpoint[1] == "1":
                        output.write(output.VerboseLevel.RESULT, "("+endpoint[2]+") ("+endpoint[3]+") "+endpoint[0]);
                output.write(output.VerboseLevel.RESULT, "");
                output.write(output.VerboseLevel.RESULT, "");
                output.write(output.VerboseLevel.RESULT, " ===  Disconnected Clients  === ");
                output.write(output.VerboseLevel.RESULT, "");
                for endpoint in clients_list:
                    if endpoint[1] == "0":
                        output.write(output.VerboseLevel.RESULT, "("+endpoint[2]+") ("+endpoint[3]+") "+endpoint[0]);

        @staticmethod
        def router_wlan(session: Session, output: Output, arg):
            """Call RouterWLAN.operate with given parameters."""
            rw = RouterWLAN(session, output);
            rw.operate(arg);

    @classmethod
    @Utilities.debug
    def main(cls, args=None):
        """Entry point."""
        cls._out = Output();
        cls._args = args;
        cls._session = Session(auto_recover_session=False, output_handler=cls._out);

        # Print the usual preamble
        cls._out.write(cls._out.VerboseLevel.INFO, cls.Messages.author);
        cls._out.write(cls._out.VerboseLevel.INFO, cls.Messages.version_s
                       % VERSION);

        # Set JSON prefences
        if RESULT_MODE == 2:
            cls._out.prefer_json = True;

        # Check if version of python is less than 3.5
        if sys.version_info[0] == 3 and sys.version_info[1] < 5:
            cls._out.write(cls._out.VerboseLevel.INFO, cls.Messages.python_version);

        # Search for the router, raise exception if it is unreachable
        cls._out.write(cls._out.VerboseLevel.INFO, cls.Messages.searching_s
                       % cls._session.ip_address);
        if not cls._session.router_reachable():
            raise Exception(cls.ErrorMessages.not_found);

        # Check if password is set otherwise prompt user for password.
        if not cls._session.password:
            # Check if CLI password parameter exists
            if (args.password is not None) and len(args.password) > 0:
                cls._out.write(cls._out.VerboseLevel.DETAILS, cls.Messages.password_set_cli);
                cls._session.password = args.password;
            else:
                cls._out.write(cls._out.VerboseLevel.DETAILS, cls.Messages.password_not_provided);
                # Ask user for password
                while not cls._session.password:
                    try:
                        cls._session.password = cls._out.read(cls.Messages.enter_password);
                    except ValueError as e:
                        cls._out.write(cls._out.VerboseLevel.INFO, e);
        else:
            # Password already exists in session
            cls._out.write(cls._out.VerboseLevel.DETAILS, cls.Messages.password_set_session);

        # Authenticate
        cls._out.write(cls._out.VerboseLevel.INFO, cls.Messages.signing_in);
        if not cls._session.sign_in():
            raise Exception(cls.ErrorMessages.sign_in_failed);

        # Check firmware compatibility
        cls._out.write(cls._out.VerboseLevel.INFO, cls.Messages.firmware_check);
        firmware_info = cls._session.get_firmware_info();
        if not firmware_info["version_validated"]:
            cls._out.write(cls._out.VerboseLevel.INFO, cls.Messages.firmware_check_report_s
                           % firmware_info["reported_version"]);

        # Jump into the user experience
        if not cls.cli_argument_available():
            cls.cli_menu_loop();

        # Sign out. If we run into an error, give the user the cookie information
        cls._out.write(cls._out.VerboseLevel.INFO, cls.Messages.signing_out);
        if not cls._session.sign_out():
            cls._out.write(cls._out.VerboseLevel.INFO, cls.ErrorMessages.sign_out_failed);
            cls._out.write(cls._out.VerboseLevel.INFO, cls._session.__repr__());

    @classmethod
    @Utilities.debug
    def cli_argument_available(cls) -> bool:
        """Process any command line argument specified.

        If any cli args are provided, (except -[-f]ormat, -[-s]ilent or -[-v]erbose) this
        returns True. Otherwise, returns False.

        @return: True if CLI arg provided, else False.
        """
        cli_arg_processed = False;

        if cls._args.clients:
            cls.Wrappers.router_clients(cls._session, cls._out);
            cli_arg_processed = True;

        if cls._args.reboot:
            cls.Wrappers.router_reboot(cls._session, cls._out);
            cli_arg_processed = True;

        if cls._args.diagnostic:
            cls.Wrappers.router_diagnostics(cls._session, cls._out);
            cli_arg_processed = True;

        if cls._args.wlan is not None:  # not None as it takes its own parameters
            cls.Wrappers.router_wlan(cls._session, cls._out, cls._args.wlan);
            cli_arg_processed = True;

        if cls._args.oids is not None:
            cls._out.write(cls._out.VerboseLevel.RESULT, cls._session.get_oids(cls._args.oids.split(",")));  # TODO: Ability to fetch SNMP objects (walk)
            cli_arg_processed = True;

        return True if cli_arg_processed else False;

    @classmethod
    @Utilities.debug
    def cli_menu_loop(cls):
        """Present the user with a CLI menu, allowing interaction with the library.

        The menu runs in a loop. The loop is broken once the user provides the "q", "exit" or "reboot" command.
        """
        help = ["",
                "   help         Show this menu",
                "   wlan 0/1     Toggle Private WLAN off/on",
                "   wlan 2/3     Toggle Guest WLAN off/on",
                "   clients      List router clients",
                "   diagnostic   View router status information",
                "   reboot       Reboot your router",
                "   q            Exit program",
                ""];

        def show_help():
            for line in help:
                cls._out.write(cls._out.VerboseLevel.INFO, line);

        show_help();
        command = "";

        while command.split(" ")[0] not in ["reboot", "q", "exit"]:
            command = cls._out.read("Enter a command");
            if command == "help":
                show_help();
            elif command.split(" ")[0] == "wlan":
                if len(command.split(" ")) > 1:
                    cls.Wrappers.router_wlan(cls._session, cls._out, command.split(" ")[1]);
                else:
                    cls._out.write(cls._out.VerboseLevel.INFO, cls.Messages.module_arguments_missing_s % "WLAN");
            elif command == "clients":
                cls.Wrappers.router_clients(cls._session, cls._out);
            elif command == "diagnostic":
                cls.Wrappers.router_diagnostics(cls._session, cls._out);
            elif command == "reboot":
                cls.Wrappers.router_reboot(cls._session, cls._out);
            else:
                pass;


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser();
    parser.add_argument("-p", "--password", help="Provide the password for the router", metavar="N");
    parser.add_argument("-c", "--clients", help="Present client information", action="store_true");
    parser.add_argument("-w", "--wlan", help="Toggle the primary WLAN off=0 or on=1. Guest WLAN off=2 or on=3. Affects both 2.4GHz and 5GHz radios.", metavar="N");
    parser.add_argument("-f", "--format", help="Present output in [j]son or [c]onsole format. Silent mode may be necessary.", metavar="X");
    parser.add_argument("-v", "--verbose", help="Enable verbose mode", action="store_true");
    parser.add_argument("-d", "--diagnostic", help="View router status", action="store_true");
    parser.add_argument("-r", "--reboot", help="Reboot your router", action="store_true");
    parser.add_argument("-s", "--silent", help="Only output result. Note: Ensure desired operation in normal mode before invoking silent mode", action="store_true");
    parser.add_argument("-o", "--oids", help="Queries a list of comma-separated OIDs. Returned in JSON format. MIB Objects not supported (yet)", metavar="X");
    args = parser.parse_args();

    if args.verbose is True and args.silent is True:
        raise Exception("Creativity is that marvelous capacity to grasp mutually distinct realities and draw a spark from their juxtaposition. - Max Ernst");
    elif args.verbose is True:
        VERBOSE_MODE = 3;
    elif args.silent is True:
        VERBOSE_MODE = 1;

    if args.format is not None:
        if args.format in ["j", "json"]:
            RESULT_MODE = 2;
        elif args.format in ["c", "console"]:
            RESULT_MODE = 0;
        else:
            raise Exception("Output format is not valid, see help -h");

    CommandLineInterface.main(args);
