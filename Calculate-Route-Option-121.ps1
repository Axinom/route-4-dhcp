# Calculates classless route hex value for DHCP option 121.
# Example usage:
# .\Calculate-Route-Option-121.ps1  10.0.0.0/8, 192.168.88.2, 172.16.0.0/12, 192.168.88.2, 192.168.0.0/16, 192.168.88.2, 0.0.0.0/0, 192.168.88.1  

[CmdletBinding()]
param(
    # An array of addresses where every odd element is a network and every even element is the IP address that should be used
    # to route traffic to that network.
    [Parameter(Mandatory = $True)]
    [string[]]
    $Routes
)

$IpRegex = "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"

# Calculates the number of octets that need to be present in the option value. 
# Currently supports only masks 8, 16, 24 and 32.
function Get-NumberOfSignificantOctets([string]$subNetMask) {
    if ($subNetMask -le 8) {
        return 1
    }
    elseif ($subNetMask -le 16) {
        return 2
    }
    elseif ($subNetMask -le 24) {
        return 3
    }
    elseif ($subNetMask -le 32) {
        return 4
    }
    else {
        return 0
    }
}

# Converts a number to base16, padding each result to 2 characters.
function Convert-ToHexadecimal([string]$network) {
    if (!$network) {
        return "00"
    }
    # Special case to get identical result with the Perl version of this script.
    if ($network -eq "0") {
        return "0"
    }

    return '{0:x2}' -f [int] $network
}

$Net, $Gateway, $Aggregate = ""

foreach ($Route in $Routes) {

    # Do not start the calculation of hex values before both values of the pair ($Net, $Gateway) have been filled.
    if (!$Net) { 
        $Net = $Route
        continue
    }

    if (!$Gateway) {

        $Gateway = $Route
        $Network, [int]$SubnetMask = $Net.split('/')

        # Calculate hex values only for correctly formatted addresses and networks.
        if ($SubnetMask -ge 0 -And $SubnetMask -le 32 -And $Network -match $IpRegex -And $Gateway -match $IpRegex) {
           
            $Destination = $Network.split('\.')
            $HexDest = ""    

            $Router = $Gateway.split('\.')
            $HexRouter = ""

            $NetworkLength = Convert-ToHexadecimal $SubnetMask

            $SignificantOctets = Get-NumberOfSignificantOctets $SubnetMask

            if ($SignificantOctets -gt 0) {
                foreach ($index in 1..$SignificantOctets) {
                    $HexDest += (Convert-ToHexadecimal $Destination[$index - 1])
                }
            }

            foreach ($r in $Router) {
                $HexRouter += (Convert-ToHexadecimal $r)
            }

            $Aggregate += "$NetworkLength$HexDest$HexRouter" 
            
            "Option 121 route $Net via $Gateway : 0x{0}{1}{2}" -f $NetworkLength, $HexDest, $HexRouter
        }
        else {
            Write-Error "Error in route $Route"
        }
    }

    # Pair successfully converted to hex, start the process from beginning with the next pair.
    $Net = "" 
    $Gateway = ""
}

if ($Aggregate) {
    Write-Output "Aggregate option 121 : $Aggregate"
}