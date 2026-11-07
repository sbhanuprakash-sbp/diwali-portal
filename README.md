# Diwali Portal

A personal Diwali greeting portal with a private admin dashboard.

**Visitor flow:** open the link → portal opens → pick who you are (Friend, Best Friend, Classmate, Siblings, Teammate, Other, or write your own) → log in with **Name** + **Secret** → personal greeting with diyas and fireworks → "Want to say something?" reply box → they can change their own Name and Secret.

**What you (admin) see** at `/admin.html`: every visit with the option picked, who logged in and how many times, failed attempts, sessions, replies, device/browser/OS, IP, CSV export, and account management (create, edit greeting/photo, disable/enable, reset secret). Secrets are stored only as bcrypt hashes, so you can reset them but never read them.

```
backend/   Flask API (app.py), requirements.txt, Procfile, .env.example
frontend/  index.html (visitors), admin.html (you), config.js (the one setting to edit), _headers
render.yaml   one-click Render setup (API + Postgres)
netlify.toml  tells Netlify to publish the frontend folder
```

---

## Run it on your computer (Windows PowerShell)

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Open `backend/.env` and fill in:

1. `JWT_SECRET`: run `py -c "import secrets; print(secrets.token_urlsafe(48))"` and paste the result.
2. `ADMIN_USERNAME`: any name you like.
3. `ADMIN_PASSWORD_HASH`: run `py -c "import bcrypt; print(bcrypt.hashpw(b'Your-Long-Admin-Password', bcrypt.gensalt()).decode())"` and paste the result.

Start the API, then in a second terminal (project root) start the pages:

```powershell
python app.py
py -m http.server 5500 --directory frontend
```

Visitor page: http://127.0.0.1:5500  ·  Admin page: http://127.0.0.1:5500/admin.html
Opened from 127.0.0.1 or localhost, both pages automatically use your local API. You don't edit anything for local testing.

---

## Deploy (about 15 minutes)

**Important:** never commit `backend/.env`. `.gitignore` already blocks it. Use a **private** GitHub repo.

### 1. Make your admin hash (on your computer)
```powershell
py -c "import bcrypt; print(bcrypt.hashpw(b'Your-Long-Admin-Password', bcrypt.gensalt()).decode())"
```
Keep that output for step 2. Use a NEW password, not one you tested with before.

### 2. Backend on Render
1. Push the project to GitHub.
2. Render → **New → Blueprint** → choose the repo. Render reads `render.yaml` and creates the API and a Postgres database.
3. When it asks for values:
   - `ADMIN_USERNAME`: your admin name
   - `ADMIN_PASSWORD_HASH`: the hash from step 1
   - `FORMSPREE_URL`: your Formspree form URL (every reply is also emailed to you). Leave empty to skip.
   - `FRONTEND_ORIGIN`: you don't know it yet, so type `https://example.com` for now
   - `JWT_SECRET` is generated for you.
4. When it finishes, open `https://YOUR-SERVICE.onrender.com/api/health`. You should see `{"status":"ok", ...}`.

### 3. Point the pages at the API
Edit **`frontend/config.js`** (the only file to edit) and set `API_BASE` to your Render URL, no slash at the end. Commit and push.

### 4. Frontend on Netlify
- **Easiest:** go to app.netlify.com/drop and drag the **`frontend`** folder in.
- Or: Netlify → Add new site → Import from Git → the repo (`netlify.toml` already sets the publish folder to `frontend`).

Copy your Netlify address (for example `https://my-diwali.netlify.app`).

### 5. Allow the frontend to talk to the API
Render → your service → **Environment** → set `FRONTEND_ORIGIN` to the exact Netlify address (https, no trailing slash). Save (Render restarts the service). You can list two addresses separated by a comma.

### 6. Create the accounts
Open `https://YOUR-SITE.netlify.app/admin.html`, sign in, open the **Accounts** tab and create one account per person (login name in lowercase, no spaces; secret 10+ characters; their personal greeting). Share each person's name + secret privately, along with the link.

### 7. Test it like a friend would
Use your phone on mobile data: open the link → pick an option → log in → send a reply → check the reply arrives in your email and in the admin Replies tab. Then delete the test data you don't want from the dashboard by simply ignoring it, or create your test account as "disabled".

---

## Good to know

- **First tap can be slow.** Render's free service sleeps when idle. The page wakes it up as soon as it opens, and the "Continue" button says so if it takes a few seconds (up to ~30 s the very first time).
- **Free Render databases are temporary** (they expire after about 30 days). That is fine for a festival surprise. Export the CSVs from the admin page before it expires.
- **Admin sees the same IP for everyone?** Set `TRUSTED_PROXIES=2` in Render and restart.
- **"Can't reach the server"?** Check that `config.js` has the right Render address and that `FRONTEND_ORIGIN` exactly matches the Netlify address.
- **Passwords:** Secrets must be 10–72 characters. Login names are 3–40 characters: lowercase letters, numbers, `.` `_` `-` (no spaces). Example: `priya.k`.
- **Lock-out:** 8 wrong secrets on one account locks it for 15 minutes. Wrong guesses are rate-limited per IP.
- **Single worker:** the rate-limit counters live in memory, so keep `--workers 1`.

## Privacy

The portal records the option picked, time, IP address, browser/device details and screen size, login attempts, sessions and replies. The visitor page tells people this. Secrets are never stored or logged in readable form, and unknown names typed at login are stored masked. Tell your friends about the dashboard if you like. Keep the admin address to yourself.
