$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw '.NET 10 SDK is not installed. Install it from https://dotnet.microsoft.com/download/dotnet/10.0'
}
dotnet restore .\XrayHub.csproj
dotnet publish .\XrayHub.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
Write-Host "Publish output: $PSScriptRoot\bin\Release\net10.0-windows\win-x64\publish\XrayHub.exe" -ForegroundColor Green
