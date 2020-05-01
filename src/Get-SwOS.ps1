function Get-SwOS
{
    [CmdletBinding(DefaultParameterSetName = 'ByPasswordSet')]
    Param(
        [Parameter()]
        [ipaddress]$IPAddress = '192.168.88.1',

        [Parameter()]
        [switch]$Detail,

        [Parameter(Mandatory, ParameterSetName = 'ByPasswordSet')]
        [string]$UserName,

        [Parameter(Mandatory, ParameterSetName = 'ByPasswordSet')]
        [SecureString]$Password,

        [Parameter(Mandatory, ParameterSetName = 'ByCredentialSet')]
        [pscredential]$Credential
    )

    $queryUrl = 'http://{0}/sys.b' -f $IPAddress.IPAddressToString

    if ($PSCmdlet.ParameterSetName -eq 'ByPasswordSet')
    {
        $Credential = [pscredential]::new($UserName, $Password)
    }

    $response = Invoke-WebRequest $queryUrl -UseBasicParsing -Credential $Credential | select -expand Content
    if (($response.Length -lt 2) -or ($response[0] -ne '{') -or ($response[$response.Length - 1] -ne '}'))
    {
        throw 'Invalid response from device'
    }

    $statMapping = @{
        'fan1' = @{ Name = 'Fan1'; Unit = 'RPM' }
        'fan2' = @{ Name = 'Fan2'; Unit = 'RPM' }
        'fan3' = @{ Name = 'Fan3'; Unit = 'RPM' }
        'fan4' = @{ Name = 'Fan4'; Unit = 'RPM' }

        'temp' = @{ Name = 'CPU Temp'; Unit = 'C' }
        'btmp' = @{ Name = 'Board Temp'; Unit = 'C' }

        'p1v' = @{ Name = 'PSU1 Voltage'; Unit = 'V' }
        'p1c' = @{ Name = 'PSU1 Current'; Unit = 'mA' }
        'p2v' = @{ Name = 'PSU2 Voltage'; Unit = 'V' }
        'p2c' = @{ Name = 'PSU2 Current'; Unit = 'mA' }

        'upt' = @{ Name = 'Uptime'; Unit = 'Duration' }

        'mac' = @{ Name = 'MAC Address'; Unit = 'MAC' }
        'rmac' = @{ Name = 'Root Bridge MAC Address'; Unit = 'MAC' }

        'ip' = @{ Name = 'IP Address'; Unit = 'IP' }
        'cip' = @{ Name = '?IP Address'; Unit = 'IP' }

        'prio' = @{ Name = 'Bridge Priority'; Unit = 'Integer' }
        'rpr' = @{ Name = 'Root Bridge Priority'; Unit = 'Integer' }

        'sid' = @{ Name = 'Serial'; Unit = 'Text' }
        'id' = @{ Name = 'Identity'; Unit = 'Text' }
        'ver' = @{ Name = 'Version'; Unit = 'Text' }
        'brd' = @{ Name = 'Board Name'; Unit = 'Text' }

        'bld' = @{ Name = 'Build Timestamp'; Unit = 'UnixTime' }

        'iptp' = @{ Name = 'Address Acquisition'; Unit = 'Option'; Map = @{ 
            0x00 = 'DHCP with fallback'
            0x01 = 'Static'
            0x02 = 'DHCP Only'
        }}
        'cost' = @{ Name = 'Port Cost Mode'; Unit = 'Option'; Map = @{ 
            0x00 = 'Short'
            0x01 = 'Long'
        }}

        'p1s' = @{ Name = 'PSU1 Online'; Unit = 'Switch' }
        'p2s' = @{ Name = 'PSU2 Online'; Unit = 'Switch' }
        'dsc' = @{ Name = 'Mikrotik Discovery Protocol'; Unit = 'Switch' }
        'ivl' = @{ Name = 'Independent VLAN Lookup'; Unit = 'Switch' }
        'wdt' = @{ Name = 'Watchdog'; Unit = 'Switch' }
        'igmp' = @{ Name = 'IGMP Snooping'; Unit = 'Switch' }
        'ainf' = @{ Name = 'Add Info Option'; Unit = 'Switch' }
    }

    $rawStats = $response.Substring(1, $response.Length - 2) -split ','
    $rawStats | ForEach-Object {
        $kvp = $_ -split ':'

        $outStat = @{
            Id = $kvp[0]
            Raw = $kvp[1]
        }

        if ($statMapping.ContainsKey($outStat.Id))
        {
            $outStat.Name = $statMapping[$outStat.Id].Name
            $outStat.Unit = $statMapping[$outStat.Id].Unit

            if ($statMapping[$outStat.Id].Unit -in @('RPM', 'C', 'mA', 'Integer'))
            {
                $outStat.Value = [int]($outStat.Raw)
            }
            elseif ($statMapping[$outStat.Id].Unit -eq 'V')
            {
                $outStat.Value = [int]($outStat.Raw) / 100
            }
            elseif ($statMapping[$outStat.Id].Unit -eq 'Duration')
            {
                $outStat.Value = [timespan]::FromMilliseconds([int]($outStat.Raw) * 10)
            }
            elseif ($statMapping[$outStat.Id].Unit -eq 'MAC')
            {
                $outStat.Value = [System.Net.NetworkInformation.PhysicalAddress]::Parse($outStat.Raw.Trim("'").ToUpperInvariant())
            }
            elseif ($statMapping[$outStat.Id].Unit -eq 'IP')
            {
                $outStat.Value = [ipaddress]::new([int]($outStat.Raw))
            }
            elseif ($statMapping[$outStat.Id].Unit -eq 'Switch')
            {
                $outStat.Value = [bool]($outStat.Raw)
            }
            elseif ($statMapping[$outStat.Id].Unit -eq 'Option')
            {
                $outStat.Value = $statMapping[$outStat.Id].Map[[int]($outStat.Raw)]
            }
            elseif ($statMapping[$outStat.Id].Unit -eq 'Text')
            {
                 $hexString = $outStat.Raw.Trim("'")
                 $decodeString = ''
                 for ($i = 0; $i -lt $hexString.Length; $i+=2)
                 {
                     $decodeString += ([char][int]('0x' + ($hexString.Substring($i, 2)))).ToString()
                 }
                 $outStat.Value = $decodeString
            }
            elseif ($statMapping[$outStat.Id].Unit -eq 'UnixTime')
            {
                 $outStat.Value = [System.DateTimeOffset]::FromUnixTimeSeconds([int]($outStat.Raw))
            }
        }

        if (-not $Detail)
        {
            $outStat.Remove('Id')
            $outStat.Remove('Raw')
        }

        if ($outStat.Count -gt 0)
        {
            [pscustomobject]$outStat
        }
    }
}
