# Create the function to create the authorization signature
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}

# Create the function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $body = ([System.Text.Encoding]::UTF8.GetBytes($json))
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $TimeStampField = Get-Date -Format "o"
    $contentLength = $body.Length

    $xHeaders = "x-ms-date:" + $rfc1123date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $signature = 'SharedKey {0}:{1}' -f $customerId,$encodedHash

    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode

}

Function Invoke-Audit{
[CmdletBinding()]
Param(
    [parameter(Mandatory=$true)]$AuditPort,
    [string]$CustomerId = $null,
    [string]$SharedKey = $null,
    [string]$LogType = $null,
    [string]$AddressPattern = '\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    [string]$OSType = 'All',
    [string]$ScanIPType = $null
)
    $SearchQuery = $true
    $ScanPublicIP = $true
    $ScanPrivateIP = $false
    if ($OSType -eq 'Linux')
    {
        $SearchQuery = '($_.OSProfile.LinuxConfiguration)'
    }
    elseif ($OSType -eq 'Windows')
    {
        $SearchQuery = '($_.OSProfile.WindowsConfiguration -or $_.LicenseType -eq "Windows_Server")'
    }

    if ($ScanIPType -eq 'All')
    {
        $ScanPrivateIP = $true
    }
    elseif ($ScanIPType -eq 'Private')
    {
        $ScanPublicIP = $false
    }
    Login-AzAccount;
    Get-AzSubscription | %{
        Select-AzSubscription -SubscriptionId $_.Id | out-null;
        get-azvm -Status | ?{(Invoke-Expression $SearchQuery) -and $_.PowerState -eq "VM running"} | %{
            $public_ip=$null;
            $public_ip_scan=$null;
            $private_ip=$null;
            $private_ip_scan=$null;
            $nic_rg = $_.NetworkProfile.NetworkInterfaces.Id.split("/")[4] ;
            $nic_name = $_.NetworkProfile.NetworkInterfaces.Id.split("/")[-1];
            $nic = Get-AzNetworkInterface -name $nic_name -ResourceGroupName $nic_rg;
            $nic_config = Get-AzNetworkInterfaceIpConfig -NetworkInterface $nic;
            $private_ip = $nic_config.PrivateIpAddress;
            if($nic_config.PublicIpAddress.Id -and $ScanPublicIP)
            {
                $pip_config = Get-AzPublicIpAddress -ResourceGroupName $nic_config.PublicIpAddress.Id.split("/")[4] -Name $nic_config.PublicIpAddress.Id.split("/")[-1];
                $public_ip=$pip_config.IpAddress;
                $public_ip_scan= nmap -Pn -p $AuditPort $public_ip | grep $AuditPort;
            }
            if($private_ip -match $AddressPattern -and $ScanPrivateIP)
            {
                $private_ip_scan= nmap -Pn -p $AuditPort $private_ip | grep $AuditPort;
            }

            if ($CustomerId -ne $false -and $SharedKey -and $CustomerId)
            {
                $json = @{  "SubscriptionId" = $_.Id.split("/")[2]; "ResourceGroup" = $_.Id.split("/")[4]; "VM" = $_.Id.split("/")[-1]; "PublicIP" = $public_ip; "PrivateIP" = $nic_config.PrivateIpAddress; "PublicIPScan" = $public_ip_scan; "PrivateIPScan" = $private_ip_scan; } | ConvertTo-Json; 
                Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType | out-null;
            }
            else
            {
                $item = New-Object PSObject;
                $item | Add-Member -type NoteProperty -Name 'SubscriptionId' -Value $_.Id.split("/")[2];
                $item | Add-Member -type NoteProperty -Name 'ResourceGroup' -Value $_.Id.split("/")[4];
                $item | Add-Member -type NoteProperty -Name 'VM' -Value $_.Id.split("/")[-1];
                $item | Add-Member -type NoteProperty -Name 'PublicIP' -Value $public_ip;
                $item | Add-Member -type NoteProperty -Name 'PrivateIP' -Value $nic_config.PrivateIpAddress;
                $item | Add-Member -type NoteProperty -Name 'PublicIPScan' -Value $public_ip_scan;
                $item | Add-Member -type NoteProperty -Name 'PrivateIPScan' -Value $private_ip_scan;
                write-output $item;
            }
    }
    }
    Logout-AzAccount | out-null;
}
