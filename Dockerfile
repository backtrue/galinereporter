# 使用官方 Python 3.10 slim 版本作為基礎映像檔 (你可以根據你的 Python 版本調整)
FROM python:3.10-slim

# 設定工作目錄
WORKDIR /app

# 將 requirements.txt 複製到容器中
COPY requirements.txt requirements.txt

# 安裝依賴套件
# --no-cache-dir 避免快取，--system 確保安裝到系統路徑 (在容器內)
RUN pip install --no-cache-dir -r requirements.txt

# 將目前目錄的內容 (你的 Flask 應用程式碼) 複製到容器的 /app 目錄中
COPY . .

# 設定 Gunicorn 運行的環境變數 (Cloud Run 會自動提供 PORT 環境變數)
# ENV PORT 8080 # Cloud Run 會自動設定，這裡可以不寫或註解掉

# 開放容器的 8080 連接埠 (Gunicorn 將會在這個連接埠上運行)
EXPOSE 8080

# 容器啟動時執行的指令
# 使用 Gunicorn 來運行 app:app (app.py 檔案中的 app Flask 實例)
# --bind 0.0.0.0:$PORT 讓 Gunicorn 監聽所有網路介面以及 Cloud Run 提供的 PORT
# --workers 建議數量通常是 (2 * CPU核心數) + 1，但 Cloud Run 可能有自己的建議，先用 1-2 個 worker 試試
# --timeout 秒數，避免長時間請求卡住 worker
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "8", "--timeout", "0", "app:app"]