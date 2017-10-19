# SuperHub-ClientsAPI
A python script for logging in to a Virgin Media Super Hub and listing connected clients in a json-compatible or list format

## Getting Started
Before running the script, you'll first need to get the authentication details for the router, 
which will be used by the python script to log in.
This can be done by logging into the router and capturing the GET request using your browser's developer tools.
You only need to capture the GET request once.

Once you have captured the GET request, in the format http://192.168.0.1/login?arg=**KEY1**&_n=**KEY2**&_=**KEY3**,
open the python file in a text editor of your choice and refill the contents in *superhub_key1*, *superhub_key2* and *superhub_key3* respectively.

While the file is still open in the text editor, you can modify the *set_verbose_mode* and *set_list_mode* outputs to
whichever valid options best suit the method of verbosity you would like from the output.

## Viewing clients
To view the connected clients, simply run the script. It will then use the details above to login, and present you with a list of connected clients.
