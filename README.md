# SuperHub3-CLI
A command-line interface and API for interacting with the Virgin Media SuperHub 3/ARRIS TG2492S/CE broadband router. Allows listing current/past connected devices, toggle private/guest WLAN, rebooting and viewing router status.

**Warning: This branch is for version 2.0.0 which is in development. Some features may be broken - please use the stable 1.x.x branch for now.**

[Read the Wiki](../../wiki)

## Screenshots

![Image showing main menu](https://i.imgur.com/G4J9A4i.png)

![Image showing router clients](https://i.imgur.com/0qvSwUM.png)

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

### Viewing router status
The router's status, such as uptime and WAN address, can be viewed through the menu, or through the `--diagnostic` command line argument.

### Rebooting the router
You can reboot the router via the menu, or through the `--reboot` command line argument.

### Query OIDs
**Dev Note: Not Documented in Wiki**
You can query a list of comma-separated OIDs using the `--oid` command line argument.

## Misc
### Output modes
Multiple output modes are available through command line arguments, such as a json-compatible output or verbose mode if desired, [see here](../../wiki/Command-Line-Arguments#other).

## Development
### Files
- `pyproject.toml` Used by [Poetry](https://python-poetry.org) for package management. If this file is modified, use `poetry check` to validate the syntax.
- `setup.cfg` Used by pycodestyle and pydocstyle.

## Feedback
### Feature Suggestions
Feel free to open a new issue with a feature suggestion, or merge request.

### Acknowledgements
Thanks to the following:

- haywirephoenix: Toggling the WLAN
- jasonchu024: Reboot and Logout OIDs
