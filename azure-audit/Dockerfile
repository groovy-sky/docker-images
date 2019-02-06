FROM mcr.microsoft.com/powershell
RUN /usr/bin/pwsh -Command "Install-Module -Name Az -AllowClobber -Scope CurrentUser -Force"
RUN apt-get update && apt-get install nmap -y
