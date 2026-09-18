@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ============================================================
echo   KakaoChatExport.exe  one-file build script
echo   KakaoTalk 聊天记录导出工具 - 一键打包
echo ============================================================
echo.

REM ---- [0] 检测 Python ----
where python >nul 2>nul
if errorlevel 1 (
    echo [X] 未找到 python。请先安装 Python 3.10+ 并勾选 "Add to PATH"。
    echo     下载: https://www.python.org/downloads/windows/
    pause
    exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo [i] Python: %%v

REM ---- [1] 安装打包依赖 ----
echo.
echo [1/4] 安装打包依赖 (pyinstaller + cryptography) ...
python -m pip install --upgrade pip >nul
python -m pip install pyinstaller cryptography
if errorlevel 1 (
    echo [X] 依赖安装失败，请检查网络或 pip 源。
    pause
    exit /b 1
)

REM ---- [2] 检查随包 sqlcipher.exe ----
echo.
echo [2/4] 检查 bin\sqlcipher.exe ...
if not exist "bin\sqlcipher.exe" (
    echo.
    echo [!] 警告: 未找到 bin\sqlcipher.exe
    echo     解密 KakaoTalk 数据库需要外部 sqlcipher.exe。
    echo     请把 Windows 版 sqlcipher.exe（及其依赖的 DLL，如 libcrypto/libssl）
    echo     放到本目录的 bin\ 文件夹后重新打包。获取方式见《打包与运行说明.md》。
    echo.
    echo     若现在继续，产物在目标机运行时会因缺 sqlcipher 而无法解密。
    choice /c YN /m "    是否仍要继续打包 (Y=继续 / N=退出)"
    if errorlevel 2 exit /b 1
) else (
    echo [OK] 已找到 bin\sqlcipher.exe，将随包打入。
)

REM ---- [3] 清理旧产物 ----
echo.
echo [3/4] 清理旧产物 ...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"

REM ---- [4] PyInstaller 打包 ----
echo.
echo [4/4] PyInstaller 打包 (onefile, 可能需要 1-3 分钟) ...
python -m PyInstaller --noconfirm KakaoChatExport.spec
if errorlevel 1 (
    echo [X] 打包失败，请查看上方错误信息。
    pause
    exit /b 1
)

echo.
echo ============================================================
if exist "dist\KakaoChatExport.exe" (
    echo   [OK] 打包成功！
    echo   产物: %cd%\dist\KakaoChatExport.exe
    echo.
    echo   下一步: 把 dist\KakaoChatExport.exe 拷到目标 Windows 电脑，
    echo           双击运行即可（目标机无需安装 Python）。
) else (
    echo   [X] 未在 dist\ 找到产物，请检查打包日志。
)
echo ============================================================
pause
endlocal
