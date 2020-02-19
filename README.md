# acme.net
IIS &amp; .Net Core implementation of the ACMEv2 Protocol Server

Designed to work with Windows CA Servers
Currently has dependencies on 2 windows COM objects (making the project not pure core), and is designed arround app settings being modified by the IIS management console (we use web.config for application settings)
