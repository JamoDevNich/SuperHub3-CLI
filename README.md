# ClientsAPI-SuperHub3
A python script for logging in to a Virgin Media Super Hub 3 and listing clients in a json-compatible or list format.

The Superhub 3 remembers clients that have previously disconnected from the router, but does not present them to the user through the main interface. This utility shows the user currently connected clients, as well as disconnected ones.

## Getting Started
### Authenticating
From version 0.1.5 onwards, authenticating simply requires your Superhub's passcode. To have the script automatically authenticate with the router, open the python file in a text editor of your choice and change the *superhub_password* variable to your hub's passcode.

### Customising Output
While the file is still open in the text editor, you can modify the *set_verbose_mode* and *set_list_mode* outputs to whichever valid options best suit the method of verbosity you would like from the output.

## Viewing Clients
To view the clients list, simply run the script. It will then use the details above to login, and present you with a list of connected clients, similar to the one shown below.

![Image](https://i.imgur.com/bkLiHQ2.png)
