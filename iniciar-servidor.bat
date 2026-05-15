@echo off
setlocal
cd /d "c:\Users\lewin\OneDrive\Desktop\Diagramas pasantia\riego-backend"

for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":3000" ^| findstr "LISTENING"') do (
  taskkill /PID %%a /F >nul 2>&1
)

start "Servidor GreenSpace" powershell -NoExit -Command "cd 'c:\Users\lewin\OneDrive\Desktop\Diagramas pasantia\riego-backend'; npm start"
