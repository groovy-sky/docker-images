FROM mcr.microsoft.com/powershell
ARG VERSION=latest
RUN /usr/bin/pwsh -Command "Install-Module -Name Az -AllowClobber -Scope CurrentUser -Force"
RUN apt-get update && apt-get install nmap -y
COPY main.psm1 /opt/microsoft/powershell/6/Modules/Microsoft.PowerShell.Audit/Microsoft.PowerShell.Audit.psm1
COPY New-SelfSignedCertificateEx.ps1 /opt/microsoft/powershell/6/Modules/Microsoft.PowerShell.Audit/New-SelfSignedCertificateEx.psm1
CMD ["/usr/bin/pwsh","-c","Invoke-Audit"]
