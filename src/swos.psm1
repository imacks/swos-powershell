Set-StrictMode -Version 3
$ErrorActionPreference = "Stop"

function Invoke-SwosRequest
{
    <#
        .SYNOPSIS
            Perform low level requests from SwOS device.

        .DESCRIPTION
            This command queries SwOS via HTTP and parses the response using regular expression.

        .PARAMETER Path
            Known paths include:

            - /link.b
            - /poe.b
            - /sfp.b
            - /fwd.b
            - /lacp.b
            - /rstp.b
            - /!stats.b
            - /host.b
            - /!dhost.b
            - /!igmp.b
            - /snmp.b
            - /acl.b
            - /sys.b
    #>

    [CmdletBinding(DefaultParameterSetName = 'ByPasswordSet')]
    Param(
        [Parameter()]
        [ipaddress]$IPAddress = '192.168.88.1',

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory, ParameterSetName = 'ByPasswordSet')]
        [string]$UserName,

        [Parameter(Mandatory, ParameterSetName = 'ByPasswordSet')]
        [SecureString]$Password,

        [Parameter(Mandatory, ParameterSetName = 'ByCredentialSet')]
        [pscredential]$Credential
    )

    # hardcoded
    $queryUrl = 'http://{0}/{1}' -f $IPAddress.IPAddressToString, $Path

    if ($PSCmdlet.ParameterSetName -eq 'ByPasswordSet')
    {
        $Credential = [pscredential]::new($UserName, $Password)
    }

    $rawResponse = Invoke-WebRequest $queryUrl -UseBasicParsing -Credential $Credential | select -expand Content

    if ($rawResponse.Length -lt 2) {
        throw 'Invalid response from device'
    }

    if (($rawResponse[0] -ne '{') -and ($rawResponse[0] -ne '[')) {
        throw 'Unexpected response from device'
    }

    if (($rawResponse[0] -eq '{') -and ($rawResponse[$rawResponse.Length - 1] -ne '}') -or 
        ($rawResponse[0] -eq '[') -and ($rawResponse[$rawResponse.Length - 1] -ne ']')
    ) {
        throw 'Malformed response from device'
    }

    # make suitable for json parser
    $rawResponse = $rawResponse -replace '{([a-z]+):', '{"$1":'
    $rawResponse = $rawResponse -replace ',([a-z]+):', ',"$1":'

    $rawResponse = $rawResponse -replace ':0x([0-9a-f]+),', ':"hex:$1",'
    $rawResponse = $rawResponse -replace ':\[0x([0-9a-f]+),', ':["hex:$1",'
    $rawResponse = $rawResponse -replace '0x([0-9a-f]+),', '"hex:$1",'
    $rawResponse = $rawResponse -replace '0x([0-9a-f]+)\]', '"hex:$1"]'
    $rawResponse = $rawResponse -replace '0x([0-9a-f]+)}', '"hex:$1"}'

    $rawResponse = $rawResponse.Replace(":'", ':"').Replace("',", '",')
    $rawResponse = $rawResponse.Replace(",'", ',"')
    $rawResponse = $rawResponse.Replace("['", '["').Replace("']", '"]')
    $rawResponse = $rawResponse.Replace("{'", '{"').Replace("'}", '"}')

    $allHexValues = [regex]::Matches($rawResponse, '"hex:[0-9a-f]+"') | select -expand Value -Unique
    $allHexValues | ForEach-Object {
        $intValue = [int]('0x' + $_.Substring(1, $_.Length - 2).Substring('hex:'.Length))
        $rawResponse = $rawResponse.Replace($_, $intValue)
    }

    # convert hex to int
    ConvertFrom-Json $rawResponse
}

function Get-SwOSInfo
{
    <#
        .SYNOPSIS
            Gets information about an SwOS device.
    #>

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

    $convertSwosParams = $PSBoundParameters
    $convertSwosParams.Remove('Detail') | Out-Null
    $swResponse = Invoke-SwosRequest @convertSwosParams -Path 'sys.b'

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

        'p1s' = @{ Name = 'PSU1 Offline'; Unit = 'Switch' }
        'p2s' = @{ Name = 'PSU2 Offline'; Unit = 'Switch' }
        'dsc' = @{ Name = 'Mikrotik Discovery Protocol'; Unit = 'Switch' }
        'ivl' = @{ Name = 'Independent VLAN Lookup'; Unit = 'Switch' }
        'wdt' = @{ Name = 'Watchdog'; Unit = 'Switch' }
        'igmp' = @{ Name = 'IGMP Snooping'; Unit = 'Switch' }
        'ainf' = @{ Name = 'Add Info Option'; Unit = 'Switch' }
    }

    Write-SwosConfig -Mapping $statMapping -Response $swResponse -Detail:$Detail
}

function Get-SwOSSnmp
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

    $convertSwosParams = $PSBoundParameters
    $convertSwosParams.Remove('Detail') | Out-Null
    $swResponse = Invoke-SwosRequest @convertSwosParams -Path 'snmp.b'

    $statMapping = @{
        'en' = @{ Name = 'Enabled'; Unit = 'Switch' }
        'com' = @{ Name = 'Community'; Unit = 'Text' }
        'ci' = @{ Name = 'Contact Info'; Unit = 'Text' }
        'loc' = @{ Name = 'Location'; Unit = 'Text' }
    }

    Write-SwosConfig -Mapping $statMapping -Response $swResponse -Detail:$Detail
}

# ---------- [ HELPERS ] ----------

function Write-SwosConfig
{
    [CmdletBinding(DefaultParameterSetName = 'ByPasswordSet')]
    Param(
        [Parameter(Mandatory)]
        [hashtable]$Mapping,

        [Parameter(Mandatory)]
        [psobject]$Response,

        [Parameter()]
        [switch]$Detail
    )

    $responseParams = $Response | Get-Member -MemberType NoteProperty | select -expand Name
    $responseParams | ForEach-Object {
        $outStat = @{
            Id = $_
            Raw = $Response."$_"
        }

        if ($Mapping[$outStat.Id].Unit -in @('RPM', 'C', 'mA', 'Integer')) {
            $outStat.Value = [int]($outStat.Raw)
        } elseif ($Mapping[$outStat.Id].Unit -eq 'V') {
            $outStat.Value = [int]($outStat.Raw) / 100
        } elseif ($Mapping[$outStat.Id].Unit -eq 'Duration') {
            $outStat.Value = [timespan]::FromMilliseconds([int]($outStat.Raw) * 10)
        } elseif ($Mapping[$outStat.Id].Unit -eq 'MAC') {
            $outStat.Value = [System.Net.NetworkInformation.PhysicalAddress]::Parse($outStat.Raw.ToUpperInvariant())
        } elseif ($Mapping[$outStat.Id].Unit -eq 'IP') {
            $outStat.Value = [ipaddress]::new([int]($outStat.Raw))
        } elseif ($Mapping[$outStat.Id].Unit -eq 'Switch') {
            $outStat.Value = [bool]($outStat.Raw)
        } elseif ($Mapping[$outStat.Id].Unit -eq 'Option') {
            $outStat.Value = $statMapping[$outStat.Id].Map[[int]($outStat.Raw)]
        } elseif ($Mapping[$outStat.Id].Unit -eq 'UnixTime') {
            $outStat.Value = [System.DateTimeOffset]::FromUnixTimeSeconds([int]($outStat.Raw))
        } elseif ($Mapping[$outStat.Id].Unit -eq 'Text') {
            $hexString = $outStat.Raw
            $decodeString = ''
            for ($i = 0; $i -lt $hexString.Length; $i += 2) {
                $decodeString += ([char][int]('0x' + ($hexString.Substring($i, 2)))).ToString()
            }
            $outStat.Value = $decodeString
        }

        if ($Mapping.ContainsKey($outStat.Id)) {
            $outStat.Name = $Mapping[$outStat.Id].Name
            $outStat.Unit = $Mapping[$outStat.Id].Unit
        }

        if (-not $Detail) {
            $outStat.Remove('Id')
            $outStat.Remove('Raw')
        }

        if ($outStat.Count -gt 0) {
            [pscustomobject]$outStat
        }
    }
}
