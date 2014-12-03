Previously named InexorablePoSH. This repo contains a .NET application that provides the capability to work around a AppLocker blacklist on the PowerShell process. It uses the backend assemblies to load and execute PowerShell.  

Many thanks to those in the offensive powershell community. This work is not ground breaking but hopefully will motivate offense and defense to understand the implications and lack of protections available.

If you have a really awesome use case, let me know! 

## Man Page
	powerpick.exe [<flag> <argument>]
	flags:
	-f <file> : Read script from specified file
	-r <resource name> : Read script from specified resource
	-d <url> : Read script from URL
	-a <delimeter> : Read script appended to current binary after specified delimeter. Delimeter should be very very unique string

More details [here](https://github.com/Veil-Framework/PowerTools)

Developed by [@sixdub](https://twitter.com/sixdub)

Part of Veil's [PowerTools](https://github.com/Veil-Framework/PowerTools)
