# PRAKTIKA
## AV database persistence and updates

The Windows service now stores antivirus databases on disk in a compact binary training format `TKAVDB1` under the service directory:

- `avdb/active.tkavdb` — currently active database;
- `avdb/backup.tkavdb` — backup made before updates;
- `avdb/default.tkavdb` — default database supplied with the product.

The binary file contains a signed manifest and signed records. The manifest stores the format version, release timestamp, record count, hash of the record payload and manifest signature. Each record stores the signature prefix, signature length, signature hash, offset interval, object type, detection name and record signature. On load the service verifies the manifest first, then verifies every record and skips records with invalid signatures.

Recovery order on startup:

1. Load `active.tkavdb` and verify manifest/records.
2. If manifest verification fails and the service has an authenticated session, force an AV database update.
3. If update is not possible or fails, restore `backup.tkavdb`.
4. If backup is missing or invalid, load the default database.

When a license is active, the refresh worker periodically updates AV databases. Before update it creates a backup, writes the updated database, reloads it, and rolls back to the backup if loading fails.


## Инсталлятор

Для финального задания добавлен инсталлятор TrayKeeper Antivirus на базе Inno Setup.

Инсталлятор выполняет следующие действия:

- включает runtime-артефакты сборки: `TrayKeeper.exe`, `TrayKeeperService.exe`, DLL/config/resource-файлы при их наличии;
- устанавливает антивирусные базы по умолчанию в `avdb/default.tkavdb` и первичную активную базу `avdb/active.tkavdb`;
- устанавливает приложение в `Program Files\TrayKeeper Antivirus`;
- регистрирует Windows-службу `TrayKeeperService` с типом запуска `SERVICE_AUTO_START`;
- запускает службу после установки;
- при удалении останавливает и удаляет службу из диспетчера служб;
- удаляет файлы приложения из каталога установки.

В CMake для MSVC включён статический runtime (`/MT` для Release), поэтому отдельный установщик VC++ Redistributable для работы приложения не требуется. Используемые WinHTTP/RPC/SCM-библиотеки являются системными компонентами Windows.

Инсталлятор собирается на GitHub Actions: workflow `windows-tray-app.yml` собирает Release-версию, готовит payload и компилирует `installer/TrayKeeperInstaller.iss`. Готовый `TrayKeeperAntivirusSetup.exe` выкладывается в артефакты сборки.
