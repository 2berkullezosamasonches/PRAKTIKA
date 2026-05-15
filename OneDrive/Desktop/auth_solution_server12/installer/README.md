# TrayKeeper Antivirus Installer

The project uses an Inno Setup based installer for the final Windows package.

## What the installer contains

The CI workflow prepares an `installer-payload` directory with all runtime artifacts required to start the product:

- `TrayKeeper.exe` graphical client;
- `TrayKeeperService.exe` Windows service;
- runtime DLL/config/resource files if they are produced by the build;
- default antivirus databases in `avdb/default.tkavdb` and `avdb/active.tkavdb`.

The CMake configuration uses the static MSVC runtime (`/MT` for Release), so no separate VC++ redistributable is required for the packaged application. System libraries such as WinHTTP, RPC and SCM are part of Windows.

## Service behavior

During installation the setup runs:

```bat
TrayKeeperService.exe install
sc start TrayKeeperService
```

The service registers itself as `SERVICE_AUTO_START`, so it starts automatically when Windows boots.

During uninstall the setup stops and deletes the service:

```bat
sc stop TrayKeeperService
sc delete TrayKeeperService
```

Then all files under the application directory are removed.

## Local build

1. Build the project in Release configuration.
2. Prepare the payload directory with the built executables and AV databases.
3. Compile `installer/TrayKeeperInstaller.iss` with Inno Setup 6.

The GitHub Actions workflow performs these steps automatically and uploads `TrayKeeperAntivirusSetup.exe` as a build artifact.
