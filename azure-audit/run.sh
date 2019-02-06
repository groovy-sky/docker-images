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
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
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

Login-AzAccount

$CustomerId = ""
$SharedKey = ""
$LogType = ""
$AuditPort = ''

# An optional field - if it is not specified, Log Analytics assumes the time is the message ingestion time
$TimeStampField = ""

Get-AzSubscription | %{
    Select-AzSubscription -SubscriptionId $_.Id | out-null; 
    get-azvm -Status | ?{($_.OSProfile.WindowsConfiguration -or $_.LicenseType -eq "Windows_Server") -and $_.PowerState -eq "VM running"} | %{ 
        $public_ip=0; 
        $public_ip_port=0; 
        $nic_rg = $_.NetworkProfile.NetworkInterfaces.Id.split("/")[4] ;
        $nic_name = $_.NetworkProfile.NetworkInterfaces.Id.split("/")[-1]; 
        $nic = Get-AzNetworkInterface -name $nic_name -ResourceGroupName $nic_rg; 
        $nic_config = Get-AzNetworkInterfaceIpConfig -NetworkInterface $nic; 
        if($nic_config.PublicIpAddress.Id){
            $pip_config = Get-AzPublicIpAddress -ResourceGroupName $nic_config.PublicIpAddress.Id.split("/")[4] -Name $nic_config.PublicIpAddress.Id.split("/")[-1]; 
            $public_ip=$pip_config.IpAddress; 
            $public_ip_port= nmap -Pn -p $AuditPort $pip_config.IpAddress | grep $AuditPort;
            $json = @{  "VM_Id" = $_.Id; "Public_IP" = $public_ip; "Private_IP" = $nic_config.PrivateIpAddress; "Public_Port_Scan" = $public_ip_port} | ConvertTo-Json; 
            Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType | out-null;
    }
}
}
