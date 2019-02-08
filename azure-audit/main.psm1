Function Invoke-Audit{
[CmdletBinding()]
Param(
      [parameter(Mandatory=$true)]$AuditPort
     )
    Login-AzAccount;
    Get-AzSubscription | %{
        Select-AzSubscription -SubscriptionId $_.Id | out-null;
        get-azvm -Status | ?{($_.OSProfile.WindowsConfiguration -or $_.LicenseType -eq "Windows_Server") -and $_.PowerState -eq "VM running"} | %{
            $public_ip=$null;
            $public_ip_scan=$null;
            $nic_rg = $_.NetworkProfile.NetworkInterfaces.Id.split("/")[4] ;
            $nic_name = $_.NetworkProfile.NetworkInterfaces.Id.split("/")[-1];
            $nic = Get-AzNetworkInterface -name $nic_name -ResourceGroupName $nic_rg;
            $nic_config = Get-AzNetworkInterfaceIpConfig -NetworkInterface $nic;
            if($nic_config.PublicIpAddress.Id){
                $pip_config = Get-AzPublicIpAddress -ResourceGroupName $nic_config.PublicIpAddress.Id.split("/")[4] -Name $nic_config.PublicIpAddress.Id.split("/")[-1];
                $public_ip=$pip_config.IpAddress;
                $public_ip_scan= nmap -Pn -p $AuditPort $public_ip | grep $AuditPort;
                $item = New-Object PSObject;
                $item | Add-Member -type NoteProperty -Name 'SubscriptionId' -Value $_.Id.split("/")[2];
                $item | Add-Member -type NoteProperty -Name 'ResourceGroup' -Value $_.Id.split("/")[4];
                $item | Add-Member -type NoteProperty -Name 'VM' -Value $_.Id.split("/")[-1];
                $item | Add-Member -type NoteProperty -Name 'PublicIP' -Value $public_ip;
                $item | Add-Member -type NoteProperty -Name 'PrivateIP' -Value $nic_config.PrivateIpAddress;
                $item | Add-Member -type NoteProperty -Name 'Result' -Value $public_ip_scan;
                write-output $item;
        }
    }
    }
}
