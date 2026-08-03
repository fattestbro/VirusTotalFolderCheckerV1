@echo off
setlocal
cd /d "%~dp0"

python -m pip install -r requirements.txt
python -m pip install -r requirements-build.txt
python -m unittest discover -s tests -v
python -m PyInstaller --noconfirm --clean --onefile --windowed --name VirusTotalFolderChecker src\virus_checker.py

echo.
echo Build complete:
echo %CD%\dist\VirusTotalFolderChecker.exe
pause
