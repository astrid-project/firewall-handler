AUTHOR Elis Lulja [@SunSince90](https://github.com/SunSince90)

# CB

CB is a rule forwarder which creates the appropriate firewall rules after 
receiving configuration [astrid-config](https://gitlab.com/astrid-repositories/wp2/astrid-config) 
and pushes them on the firewall of the pods involved.

## Installation

To run this, execute ``cb`` in the root folder

## API

Resources  | URLs | XML repr | Meaning
------------- | ------------- | ------------- | -------------
ROOT  | / | Rules configuration | Receive configuration from verefoo
