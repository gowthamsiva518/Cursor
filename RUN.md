# How to run the agent

## Option 1: Flask (recommended – one command)

1. **Open a terminal** and go to this project folder:
   ```
   cd c:\Users\GowthamM\Desktop\Cursor
   ```

2. **Install Python dependencies** (once):
   ```
   pip install -r requirements.txt
   ```
   If `pip` is not found, try:
   ```
   python -m pip install -r requirements.txt
   ```

3. **Start the server:**
   ```
   python app.py
   ```

4. **Open in browser:**  
   **http://127.0.0.1:5000**

5. **Check it’s working:**  
   Open **http://127.0.0.1:5000/api/health** – you should see `{"ok": true, "config": "..."}`.

---

## Option 2: Next.js

1. **Install Python deps** (for the agent backend):
   ```
   cd c:\Users\GowthamM\Desktop\Cursor
   pip install -r requirements.txt
   ```

2. **Install Node and start Next.js:**
   ```
   npm install
   npm run dev
   ```

3. **Open:** **http://localhost:3000**

If you see “Failed to run Python agent”, run Flask as in Option 1 and set:
   ```
   set AGENT_API_URL=http://127.0.0.1:5000
   ```
   then run `npm run dev` again so Next.js uses Flask for the agent.

---

## If something doesn’t work

- **“Config not found”** → You’re not in the project folder. Use `cd c:\Users\GowthamM\Desktop\Cursor` first.
- **“pip/python not recognized”** → Install Python from python.org and tick “Add Python to PATH”, or use the full path to `python.exe`.
- **Port 5000 already in use** → Stop the other app using port 5000, or in `app.py` change `port=5000` to another port (e.g. 5001) and open that port in the browser.
- **Blank page or 500 error** → Open http://127.0.0.1:5000/api/health; if that fails, check the terminal for the exact error message.
