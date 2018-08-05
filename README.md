# ClientsAPI-SuperHub3
Lists clients connected to a Virgin Media Super Hub 3 and allows toggling of WLAN/WiFi. Outputs in list or json format. 

The Superhub 3 remembers clients that have previously disconnected from the router, but does not present them to the user through the main interface. This utility shows the user currently connected clients, as well as disconnected ones.

## Getting Started
### Requirements
Python 3.3 and above, tested on both Windows and Linux. No third party libraries necessary.

### Authenticating
There are several ways to authenticate with your SuperHub. The easiest way is to run the script and type your password when prompted. Alternatively, the password can be provided via the command line argument `--password`, or if you so desire, permanently edited into the script through the `superhub_password` variable.

### Output modes
There are a variety of output modes available through command line arguments. The `--format` argument allows you to specify a `json` or `console` output format, where the latter is the default. When outputting in json format, using the `--silent` switch is recommended as this will only output the result of the request. A `--verbose` mode is also available.

## Functions
### Toggling Guest and Private WLAN
The guest networks and private WLAN networks can be toggled via the menu, or by specifying the `--wlan` argument. The parameters are as follows: 0-Disable Private Wlan, 1-Enable Private WLAN, 2-Disable Guest WLAN, 3-Enable Guest WLAN. The Guest WLAN may not be available when the private WLAN is deactivated.

This utility will overwrite the default username and password for your Guest WLAN when toggling it on, as the factory firmware may not have configured guest network credentials. However, these credentials can be set in the code variable `superhub_guestnet_config`.

### Viewing connected clients
To view the clients list, simply run the script and type the **client** option in the menu. Alternatively you can specify the `--clients` command line option. You will be presented with a list of connected and previously connected clients, similar to the one shown below.

![Image](https://i.imgur.com/bkLiHQ2.png)
