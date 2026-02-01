param([Parameter(Mandatory)] [string] $Target)
if (-not (Test-Path -Path $Target)) {
    Write-Host "File '$Target' does not exists"
    exit 1
}

$commands = "makecert.exe", "signtool.exe"
$missing = $commands | Where-Object {
    -not (Get-Command $_ -ErrorAction SilentlyContinue)
}

if ($missing) {
    Write-Host "Missing commands: $($missing -join ', ')"
    Write-Host "You may not be running inside a VS Developer Shell."
    exit 1
}

if (-not (Test-Path "$PSScriptRoot\DriverCertificate.cer")) {
    Write-Host "Generating new certificate"
    & makecert.exe -r -pe -ss PrivateCertStore -n CN=DriverCertificate $PSScriptRoot\DriverCertificate.cer
    if (-not $?) {
        Write-Host "Failed to generate certificate"
        exit 1
    }
}
else {
    Write-Host "Certificate already exists"
}

Write-Host "Signing"
signtool.exe sign /a /v /s PrivateCertStore /n DriverCertificate /t http://timestamp.digicert.com /fd SHA256 $Target
if (-not $?) {
    Write-Host "Failed to sign target"
    exit 1
}