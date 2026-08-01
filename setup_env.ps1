# setup_env.ps1

$ErrorActionPreference = "Stop"

Write-Host "Creating target directories..."
$targetDir = "C:\Users\user\PortableDev"
if (!(Test-Path $targetDir)) {
    New-Item -ItemType Directory -Force -Path $targetDir
}
if (!(Test-Path "$targetDir\JDK")) {
    New-Item -ItemType Directory -Force -Path "$targetDir\JDK"
}
if (!(Test-Path "$targetDir\Flutter")) {
    New-Item -ItemType Directory -Force -Path "$targetDir\Flutter"
}

# 1. Download OpenJDK 17
Write-Host "Downloading OpenJDK 17..."
$jdkZip = "$targetDir\jdk.zip"
if (!(Test-Path $jdkZip)) {
    curl.exe -L "https://api.adoptium.net/v3/binary/latest/17/ga/windows/x64/jdk/hotspot/normal/eclipse" -o $jdkZip
}

# 2. Extract OpenJDK 17
Write-Host "Extracting OpenJDK 17 using tar..."
tar.exe -xf $jdkZip -C "$targetDir\JDK"

# 3. Download Flutter 3.22.2
Write-Host "Downloading Flutter 3.22.2..."
$flutterZip = "$targetDir\flutter.zip"
if (!(Test-Path $flutterZip)) {
    curl.exe -L "https://storage.googleapis.com/flutter_infra_release/releases/stable/windows/flutter_windows_3.22.2-stable.zip" -o $flutterZip
}

# 4. Extract Flutter 3.22.2
Write-Host "Extracting Flutter 3.22.2 using tar..."
tar.exe -xf $flutterZip -C "$targetDir\Flutter"

# Clean up zip files to free space
Write-Host "Cleaning up ZIP files..."
if (Test-Path $jdkZip) { Remove-Item -Force $jdkZip }
if (Test-Path $flutterZip) { Remove-Item -Force $flutterZip }

Write-Host "Toolchains download and extraction completed successfully!"
