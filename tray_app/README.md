# Tray Keeper

Графическое приложение для Windows на C++ и Win32 API в тёмном готическом стиле.

## Что реализовано по заданию

- При запуске добавляется иконка в область уведомлений панели задач.
- Левый клик по иконке открывает главное окно.
- Правый клик по иконке открывает контекстное меню.
- В контекстном меню есть пункты **Открыть** и **Выход**.
- При пересоздании панели задач Windows иконка добавляется заново через сообщение `TaskbarCreated`.
- Поддерживается запуск без показа главного окна: `TrayKeeper.exe --hidden`.
- Закрытие главного окна скрывает окно, но приложение продолжает работать в фоне.
- В главном окне есть меню **Файл -> Выход**.
- Повторный запуск для того же пользователя блокируется именованным mutex до добавления иконки в трей.
- Сборка настроена через CMake.
- В GitHub Actions настроен Windows-конвейер сборки, который публикует `.exe` как artifact.


В проекте изменены название, оформление окна и иконка:

- тёмная цветовая схема;
- бордовые акценты;
- декоративный текст в стиле dark app;
- отдельное имя приложения: **Tray Keeper**.

## Локальная сборка на Windows

Нужно установить:

1. Visual Studio 2022 Community с компонентом **Desktop development with C++**.
2. CMake. Можно поставить вместе с Visual Studio.
3. Git.

Команды:

```powershell
cd tray_app
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Готовый файл будет здесь:

```text
tray_app/build/Release/TrayKeeper.exe
```

Запуск в фоновом режиме без главного окна:

```powershell
.\build\Release\TrayKeeper.exe --hidden
```

## Как сдавать

1. Создать ветку от `main`, например `feature/tray-keeper`.
2. Добавить папку `tray_app/` и workflow `.github/workflows/windows-tray-app.yml`.
3. Сделать commit и push.
4. Открыть GitHub Pull Request или GitLab Merge Request.
5. В ответ на задание вставить кликабельную ссылку на PR/MR.

Важно: по условию сдаётся не архив, а ссылка на Pull Request / Merge Request.


## Если русский текст отображается кракозябрами

Проект собирается с параметром MSVC `/utf-8`. После обновления файлов обязательно пересоберите проект с нуля:

```powershell
Remove-Item -Recurse -Force build
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Если запускался старый exe, закройте его через пункт меню трея `Выход`, затем запустите свежий `build/Release/TrayKeeper.exe`.
