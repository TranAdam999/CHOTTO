@echo off
REM Đóng gói CHOTTO (không hiện cửa sổ console). Cần: pip install -r requirements.txt
REM Dùng --onedir thay vì --onefile: bản onefile phải giải nén ra %TEMP% mỗi lần bấm link
REM (chậm 1-3 giây, dễ bị antivirus chặn), không hợp với vai trò trình duyệt mặc định.
setlocal
cd /d "%~dp0\.."
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
if errorlevel 1 (
    echo Can Python 3.11 tro len.
    exit /b 1
)
pyinstaller --noconfirm --clean --noconsole --onedir --name CHOTTO ^
    --add-data "chotto\data;chotto\data" ^
    main.py
if errorlevel 1 (
    echo Dong goi that bai.
    exit /b 1
)
echo Xong: dist\CHOTTO\CHOTTO.exe
echo Chep ca thu muc dist\CHOTTO toi vi tri co dinh (vd. %%LOCALAPPDATA%%\Programs\CHOTTO) roi chay: CHOTTO.exe install
endlocal
