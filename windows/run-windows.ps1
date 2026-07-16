$ErrorActionPreference = 'Stop'

$RepoRaw = 'https://raw.githubusercontent.com/leric1977/udp-flow-limit-test/main'
$WorkDir = 'C:\2'
$ClientPath = Join-Path $WorkDir 'udp_flow_client.py'

New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
Write-Host 'Downloading the latest Windows client...'
Invoke-WebRequest -UseBasicParsing -Uri "$RepoRaw/windows/udp_flow_client.py" -OutFile $ClientPath

$PythonCommand = $null
$PythonArgs = @()
if (Get-Command python.exe -ErrorAction SilentlyContinue) {
    $PythonCommand = 'python.exe'
}
elseif (Get-Command py.exe -ErrorAction SilentlyContinue) {
    $PythonCommand = 'py.exe'
    $PythonArgs = @('-3')
}
elseif (Get-Command python3.exe -ErrorAction SilentlyContinue) {
    $PythonCommand = 'python3.exe'
}
else {
    throw 'Python 3 was not found. Install Python 3 and enable Add Python to PATH.'
}

Write-Host "Starting: $PythonCommand $($PythonArgs -join ' ') $ClientPath"
& $PythonCommand @PythonArgs $ClientPath
exit $LASTEXITCODE
