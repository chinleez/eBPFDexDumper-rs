param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Apk,
    [Parameter(Position = 1)]
    [string]$OutputDir
)

$pythonArgs = @()
if ($env:PYTHON) {
    $python = $env:PYTHON
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $python = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $python = "py"
    $pythonArgs += "-3"
} else {
    Write-Error "Python 3.9+ was not found. Install Python or set PYTHON=/path/to/python."
    exit 1
}

$pythonArgs += (Join-Path $PSScriptRoot "run_dump.py")
$pythonArgs += $Apk
if ($OutputDir) {
    $pythonArgs += $OutputDir
}

& $python @pythonArgs
exit $LASTEXITCODE
