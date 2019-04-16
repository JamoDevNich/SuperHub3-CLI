# ClientsAPI-SuperHub3
A command-line interface for managing the VM SuperHub 3/ARRIS TG2492S/CE router. Allows listing connected devices, toggle private and guest WLAN, and rebooting.

[Read the Wiki](../../wiki)

The Superhub 3 remembers clients that have previously disconnected from the router, but does not present them to the user through the main interface. This utility shows the user currently connected clients, as well as disconnected ones.

## Screenshots
### Main Menu

![Image showing main menu](https://i.imgur.com/LG0UMOC.png)

### Viewing Clients

![Image showing router clients](https://i.imgur.com/N4pZNBb.png)

## Getting Started
### Requirements
Python 3.5 and above, tested on both Windows and Linux. No third party libraries necessary.

### Authenticating
There are several ways to authenticate with your SuperHub. The easiest way is to run the script and type your password when prompted. The password can also be provided via the command line argument `--password`.

## Functions
### Toggling WLANs
The Guest and Private WLANs can be toggled via the menu, or via the `--wlan` argument. Toggling the Guest WLAN will change some user-defined settings on your router, [see here](../../wiki/Functions-Documentation#wlan).

### Viewing clients
The router's clients can be viewed through the menu, or through the `--clients` command line argument.

### Rebooting the router
You can reboot the router via the menu, or through the `--reboot` command line argument.

## Misc
### Output modes
Multiple output modes are available through command line arguments, such as a json-compatible output or verbose mode if desired, [see here](../../wiki/Command-Line-Arguments#other).

## Feedback
### Feature Suggestions
Feel free to open a new issue with a feature suggestion, or merge request.

### Acknowledgements
Thanks to the following:

- haywirephoenix: Toggling the WLAN
- jasonchu024: Reboot and Logout OIDs
