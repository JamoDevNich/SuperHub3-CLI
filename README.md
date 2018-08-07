# ClientsAPI-SuperHub3
Lists clients connected to a Virgin Media Super Hub 3 and allows toggling of WLAN/WiFi. Outputs in list or json format. 

[Read the Wiki](./wiki)

The Superhub 3 remembers clients that have previously disconnected from the router, but does not present them to the user through the main interface. This utility shows the user currently connected clients, as well as disconnected ones.

## Getting Started
### Requirements
Python 3.3 and above, tested on both Windows and Linux. No third party libraries necessary.

### Authenticating
There are several ways to authenticate with your SuperHub. The easiest way is to run the script and type your password when prompted. The password can also be provided via the command line argument `--password`.

## Functions
### Toggling Guest and Private WLAN
The Guest and Private WLANs can be toggled via the menu, or via the `--wlan` argument. Toggling the Guest WLAN will change some user-defined settings on your router, [see here](./wiki/Functions-Documentation#wlan).

### Viewing router clients
The router's clients can be viewed through the menu, or through the `--clients` command line option.

![Image showing router clients](https://i.imgur.com/L1low59.png)

## Misc
### Output modes
There are a variety of output modes available through command line arguments, such as json-compatible output or a verbose mode if desired, [see here](./wiki/Command-Line-Arguments#other).

### Feature suggestions
Feel free to open a new issue with a feature suggestion, or fork/pull request.
