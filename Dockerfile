FROM mcr.microsoft.com/powershell
RUN /usr/bin/pwsh -Command "Install-Module -Name Az -AllowClobber -Scope CurrentUser -Force"
