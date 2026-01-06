@echo off
title SERVIDOR - ALMACEN RBYRD ONLINE (OPCION 2)
echo =========================================================
echo  INICIANDO SERVIDOR ALMACEN RBYRD ONLINE (API + POSTGRES)
echo  Puerto: 8000
echo  Endpoints:
echo    - http://127.0.0.1:8000/health
echo    - http://127.0.0.1:8000/version
echo    - http://127.0.0.1:8000/docs
echo =========================================================
echo.
echo IMPORTANTE:
echo  - Debes tener configurado DATABASE_URL (Postgres) y JWT_SECRET (recomendado).
echo  - Ejemplo (PowerShell):
echo      setx DATABASE_URL "postgresql://user:pass@host:5432/db"
echo      setx JWT_SECRET "pon-un-secreto-largo"
echo.
cd /d "%~dp0"

REM Arranca uvicorn usando Python (para pruebas locales)
py -m uvicorn online_server:app --host 0.0.0.0 --port 8000

echo.
echo El servidor se ha detenido.
pause
