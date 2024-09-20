function Convert-BitmaskToPorts {
    param (
        [string]$Bitmask
    )
    $binaryString = [convert]::ToString([convert]::ToInt64($Bitmask, 16), 2).PadLeft($Bitmask.Length * 4, '0')
    $ports = @()
    $portCount = 48
    
    for ($i = 0; $i -lt $portCount; $i++) {
        if ($binaryString[$i] -eq '1') {
            # Ports are typically numbered from 1 to 48
            $portNumber = $i + 1
            $ports += $portNumber
        }
    }
    $ports = $ports | Sort-Object
    return $ports
}

function Get-MacAddressTable
{
	[CmdletBinding()]
	param(
	[Parameter(Mandatory=$true)]
	[String]$switchIP,

	[Parameter(Mandatory=$true)]
	[String]$vlan,
	
	[Parameter(Mandatory=$true)]
	[String]$community,
	
	[Parameter(Mandatory=$true)]
	[ValidateSet('cisco','ciscosmb','hp')]
	[String]$vendor
	)
	if($vendor -eq "cisco")
	{
		#constraints
		$comstring = $community + "@" + $vlan;
		$dot1dTpFdbAddress = "1.3.6.1.2.1.17.4.3.1.1";
		$dot1dTpFdbPort = "1.3.6.1.2.1.17.4.3.1.2";
		$dot1dBasePortIfIndex ="1.3.6.1.2.1.17.1.4.1.2";
		$ifName = "1.3.6.1.2.1.31.1.1.1.1";
		
		#process
		Write-Host "Gathering MAC Addresses from: " $switchIP "and Vlan: " $vlan;
		$macaddressesdecimal = Invoke-SnmpWalk -IpAddress $switchIP -Oid $dot1dTpFdbAddress -Community $comstring | select OID | foreach {$mac = $_ -split $dot1dTpFdbAddress; $intmac = $mac.GetValue(1); $le = $intmac.Length; $address = $intmac.Substring(1,($le -2)); $address}
		$macaddresses = $macaddressesdecimal | foreach {$mac = ""; $decimals = $_ -split ('\.'); $decimals | foreach {$mac +="{0:x2}" -f ([Int32]$_) + ":";}; $_ + "," + $mac}
		$macaddressestable = $macaddresses | foreach {$le = $_.length; $_.Substring(0, ($le -1))} | ConvertFrom-Csv -Header MacAddressDec, MacAddressHex
		$ports = Invoke-SnmpWalk -IpAddress $switchIP -Oid $dot1dTpFdbPort -Community $comstring
		$ports = $ports | select OID, Value
		$portvals = $macaddressestable | foreach {$portvals = $ports | Select-String $_.MacAddressDec; try{$portstring = $portvals.ToString()}catch{}; $val = $portstring -split('Value='); try{$portval = $val[1].Replace('}', '')}catch{""}; $_.MacAddressDec + "," + $_.MacAddressHex + "," + $portval}
		$macaddressestable = $portvals | ConvertFrom-Csv -Header MacAddressDec, MacAddressHex, PortValue
		$portsdescindex = Invoke-SnmpWalk -IpAddress $switchIP -Community $comstring -Oid $dot1dBasePortIfIndex
		$portsdescindexvals = $macaddressestable | foreach {$portindex = $portsdescindex | Select-String ($dot1dBasePortIfIndex + "." + $_.PortValue + ";"); $portindex = try{$portindex.ToString()}catch{}; $indexval = $portindex -split('Value='); $indexvalstring = try{$indexval[1].Replace('}', '')}catch{""}; $_.MacAddressDec + "," + $_.MacAddressHex + "," + $_.PortValue + "," + $indexvalstring}
		$macaddressestable = $portsdescindexvals | ConvertFrom-Csv -Header MacAddressDec, MacAddressHex, PortValue, PortDescIndex
		$portsdescriptions = Invoke-SnmpWalk -IpAddress $switchIP -Community $comstring -Oid $ifName
		$portsdescriptionvals = $macaddressestable | foreach {$portdescs = $portsdescriptions | Select-String ($ifName + "." + $_.PortDescIndex + ";"); $portdescs = try{$portdescs.ToString()}catch{}; $descval = $portdescs -split('Value='); $descvalstring = try{$descval[1].Replace('}', '')}catch{""}; $_.MacAddressDec + "," + $_.MacAddressHex + "," + $_.PortValue + "," + $_.PortDescIndex + "," + $descvalstring}
		$macaddressestable = $portsdescriptionvals | ConvertFrom-Csv -Header MacAddressDec, MacAddressHex, PortValue, PortDescIndex, PortDescription
		$macaddressestable = $macaddressestable | where {$_.PortDescription -notlike "Po*" -AND $_.PortDescription -ne $null} | select MacAddressHex, PortDescription
		#$macaddressestable = $macaddressestable | group PortDescription | where {$_.Count -eq 1} | select -ExpandProperty Group
		$macaddressestable
	}
	if($vendor -eq "hp")
	{
		#constraints
		$dot1dTpFdbPort = "1.3.6.1.2.1.17.4.3.1.2"
		$ifDescr = "1.3.6.1.2.1.2.2.1.2"
		$dot1qPvid = "1.3.6.1.2.1.17.7.1.4.5.1.1"
		
		#process
		Write-Host "Gathering MAC Addresses from: " $switchIP "and Vlan: " $vlan;
		$vlanports = Invoke-SnmpWalk -IpAddress $switchIP -Community $community -Oid $dot1qPvid | Where {$_.Value -eq $vlan}
		$ports = $vlanports | select OID | foreach {$prts = $_ -split $dot1qPvid; $pp = $prts.GetValue(1); $le = $pp.Length; $port = $pp.Substring(1,($le -2)); $port}
		$descports = Invoke-SnmpWalk -IpAddress $switchIP -Community $community -Oid $ifDescr
		$vlanportsdesc = foreach($port in $ports){$descports | where {$_.OID -eq ($ifDescr + "." + "$port")}}
		$vlanportsdesc = $vlanportsdesc | select @{n="OID";e={$v=($_.OID -split $ifDescr); $nu = $v.GetValue(1); $nu.Substring(1)}}, Value
		$macs = Invoke-SnmpWalk -IpAddress $switchIP -Community $community -Oid $dot1dTpFdbPort
		$matches = foreach($pdesc in $vlanportsdesc){$pdesc.Value + "," + ($macs | where {$_.Value -eq $pdesc.OID} | select OID)}
		$matchesnorm = $matches | ConvertFrom-Csv -Header "PortDescription", "MacString" | where {$_.MacString -ne $null}
		#$matchesnorm = $matchesnorm | group PortDescription | where {$_.Count -eq 1} | select -ExpandProperty Group
		$matchesdec = $matchesnorm | select @{n="MacAddressDec";e={$mv = $_.MacString -split $dot1dTpFdbPort; $intmac=$mv.GetValue(1); $le = $intmac.Length; $address = $intmac.Substring(1,($le -2)); $address}}, PortDescription
		$macsn = $matchesdec | foreach {$md = $_.MacAddressDec; $mac = ""; $decimals = $md -split ('\.'); $decimals | foreach {$mac +="{0:x2}" -f ([Int32]$_) + ":";}; $md + "," + $mac + "," + $_.PortDescription} | ConvertFrom-Csv -Header MacAddressDec, MacAddressHex, PortDescription
		$macaddressestable = $macsn | select @{n="MacAddressHex";e={$ma = $_.MacAddressHex; $le = $ma.Length; $ma.Substring(0, ($le - 1))}}, PortDescription
		#$macaddressestable = $macaddressestable | group PortDescription | where {$_.Count -eq 1} | select -ExpandProperty Group
		$macaddressestable
	}
	if($vendor -eq "ciscosmb")
	{
		#constraints
		$dot1dTpFdbAddress = "1.3.6.1.2.1.17.4.3.1.1";
		$dot1dTpFdbPort = "1.3.6.1.2.1.17.4.3.1.2";
		$dot1dBasePortIfIndex ="1.3.6.1.2.1.17.1.4.1.2";
		$ifName = "1.3.6.1.2.1.31.1.1.1.1";
		$dot1qVlanCurrentEgressPorts ="1.3.6.1.2.1.17.7.1.4.2.1.4";
		
		#process
		Write-Host "Gathering MAC Addresses from: " $switchIP "and Vlan: " $vlan;
        	$vlanports = Invoke-SnmpWalk -IpAddress $switchIP -Oid $dot1qVlanCurrentEgressPorts -Community $community
        	$hexports = $vlanports | where {$_.OID -eq ("1.3.6.1.2.1.17.7.1.4.2.1.4.0." + $vlan)} | select -ExpandProperty Value
		if($hexports -ne $null)
		{
			$hexport = $hexports.Replace(' ','').Substring(0,16)
			$vports = Convert-BitmaskToPorts -Bitmask $hexport
		}
		else{$vports = $null}
		$macaddressesdecimal = Invoke-SnmpWalk -IpAddress $switchIP -Oid $dot1dTpFdbAddress -Community $community | select OID | foreach {$mac = $_ -split $dot1dTpFdbAddress; $intmac = $mac.GetValue(1); $le = $intmac.Length; $address = $intmac.Substring(1,($le -2)); $address}
		$macaddresses = $macaddressesdecimal | foreach {$mac = ""; $decimals = $_ -split ('\.'); $decimals | foreach {$mac +="{0:x2}" -f ([Int32]$_) + ":";}; $_ + "," + $mac}
		$macaddressestable = $macaddresses | foreach {$le = $_.length; $_.Substring(0, ($le -1))} | ConvertFrom-Csv -Header MacAddressDec, MacAddressHex
		$ports = Invoke-SnmpWalk -IpAddress $switchIP -Oid $dot1dTpFdbPort -Community $community
		$ports = $ports | select OID, Value
		$portvals = $macaddressestable | foreach {$portvals = $ports | Select-String $_.MacAddressDec; try{$portstring = $portvals.ToString()}catch{}; $val = $portstring -split('Value='); try{$portval = $val[1].Replace('}', '')}catch{""}; $_.MacAddressDec + "," + $_.MacAddressHex + "," + $portval}
		$macaddressestable = $portvals | ConvertFrom-Csv -Header MacAddressDec, MacAddressHex, PortValue
        	$macaddressestable = $macaddressestable | where {$vports -contains $_.PortValue}
		$portsdescindex = Invoke-SnmpWalk -IpAddress $switchIP -Community $community -Oid $dot1dBasePortIfIndex
		$portsdescindexvals = $macaddressestable | foreach {$portindex = $portsdescindex | Select-String ($dot1dBasePortIfIndex + "." + $_.PortValue + ";"); $portindex = try{$portindex.ToString()}catch{}; $indexval = $portindex -split('Value='); $indexvalstring = try{$indexval[1].Replace('}', '')}catch{""}; $_.MacAddressDec + "," + $_.MacAddressHex + "," + $_.PortValue + "," + $indexvalstring}
		$macaddressestable = $portsdescindexvals | ConvertFrom-Csv -Header MacAddressDec, MacAddressHex, PortValue, PortDescIndex
		$portsdescriptions = Invoke-SnmpWalk -IpAddress $switchIP -Community $community -Oid $ifName
		$portsdescriptionvals = $macaddressestable | foreach {$portdescs = $portsdescriptions | Select-String ($ifName + "." + $_.PortDescIndex + ";"); $portdescs = try{$portdescs.ToString()}catch{}; $descval = $portdescs -split('Value='); $descvalstring = try{$descval[1].Replace('}', '')}catch{""}; $_.MacAddressDec + "," + $_.MacAddressHex + "," + $_.PortValue + "," + $_.PortDescIndex + "," + $descvalstring}
		$macaddressestable = $portsdescriptionvals | ConvertFrom-Csv -Header MacAddressDec, MacAddressHex, PortValue, PortDescIndex, PortDescription
		$macaddressestable = $macaddressestable | where {$_.PortDescription -notlike "Po*" -AND $_.PortDescription -ne $null} | select MacAddressHex, PortDescription
		#$macaddressestable = $macaddressestable | group PortDescription | where {$_.Count -eq 1} | select -ExpandProperty Group
		$macaddressestable
	}
}
