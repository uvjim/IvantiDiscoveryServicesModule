# IvantiDiscoveryServicesModule
PowerShell module for working with the on-premise version of Ivanti Discovery Services.

The on-premise version of Ivanti Discovery Services is installed as part of the Endpoint Manager installation as of version 2017.1.  Discovery Services acts as a repository for inventory information for the devices in your estate.

It has a RESTful API which allows upload of data to the repository as well as subsequent querying of that data.  The description for the Discovery Services REST API can be found at ```https://<discovery_server>/discovery/api/v1/redoc``` - replace ```<discovery_server>``` with the address of your Ivanti Disocvery Services server.

Releases as well as source can be found in this repository.  Examples are provided in a script which is also avaialble in the repository.
