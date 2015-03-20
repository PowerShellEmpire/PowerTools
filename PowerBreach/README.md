# PowerBreach
PowerBreach is a backdoor toolkit that aims to provide the user a wide variety of methods to backdoor a system. It focuses on diversifying the "trigger" methods which allows the user flexibility on how to signal to the backdoor that it needs to phone home. PowerBreach focuses on memory only methods that do not persist across a reboot without further assistance and is not a silver bullet when it comes to cover communications. 

Developed by [@sixdub](https://twitter.com/sixdub)

The following people helped or aided the work directly or indirectly:

Part of Veil's [PowerTools](https://github.com/Veil-Framework/PowerTools)


## Helper Functions:
    Add-PSFirewallRules - Adds powershell to the firewall on 65K ports. Required Admin
    Invoke-CallbackIEX - The location for the various callback mechanisms. Calls back and executes encoded payload.

## Backdoors Available:
    Invoke-EventLogBackdoor: Monitors for failed RDP login attempts. Admin-Yes, Firewall-No, Auditing Reqd
    Invoke-PortBindBackdoor: Binds to TCP Port. Admin-No, Firewall-Yes
    Invoke-ResolverBackdoor: Resolves name to decide when to callback. Admin-No, Firewall-No
    Invoke-PortKnockBackdoor: Starts sniffer looking for trigger. Admin-Yes, Firewall-Yes
    Invoke-LoopBackdoor: Callsback on set interval. Admin-No, Firewall-No
    Invoke-DeadUserBackdoor: Looks for "dead" user and calls back when does not exist. Admin-No, Firewall-No

## Callback URIs Available:
    http://<host:port/resource> - Perform standard http callback
    https://<host:port/resource> - Perform standard https callback
    dnstxt://<host> - Resolve DNS text record for host which is the payload
