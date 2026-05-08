# TrayKeeper authentication and license activation

Client-side update for the Windows service and tray GUI.

The service communicates with the server from task 1.2 over HTTPS:

- `POST https://localhost:8443/api/auth/login`
- `POST https://localhost:8443/api/auth/refresh`
- `POST https://localhost:8443/api/licenses/check`
- `POST https://localhost:8443/api/licenses/activate`

Implemented in the service:

- user authentication through HTTPS login;
- access and refresh JWT tokens are stored only in service RAM;
- periodic JWT refresh based on token expiration time;
- logout clears access token, refresh token and license ticket from RAM;
- license status request through HTTPS;
- product activation through HTTPS;
- license ticket is stored only in service RAM;
- JWT tokens and license ticket are not returned to client applications;
- RPC interfaces for current user, login, logout, license info and activation;
- antivirus-related RPC access is denied when there is no active license.

Implemented in the GUI:

- requests current authenticated user at startup;
- shows login form when there is no authenticated user;
- blocks antivirus functionality when there is no user or no license;
- shows login errors and activation errors;
- shows authenticated username;
- requests license status after login;
- shows activation form when license is missing;
- shows license expiration date when license is active;
- periodically polls service license state through RPC.

Build:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Service executable:

```text
build\bin\Release\TrayKeeperService.exe
```

Tray executable:

```text
build\bin\Release\TrayKeeper.exe
```
