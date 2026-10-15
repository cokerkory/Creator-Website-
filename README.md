# Victor Coker Personal Website

A responsive personal portfolio made with HTML, CSS, browser JavaScript, and a Node.js/Express backend. Registration and login use SQLite, password hashing, and server-side sessions.

## Requirements
- Node.js 18 or newer
- npm

## Run locally
1. Extract the ZIP file.
2. Open a terminal in the extracted `victor_coker_fullstack` folder.
3. Run `npm install`.
4. Set a session secret, then run the server.

Windows PowerShell:
```powershell
$env:SESSION_SECRET = "replace-this-with-a-long-random-secret-value"
npm start
```

macOS/Linux:
```bash
export SESSION_SECRET="replace-this-with-a-long-random-secret-value"
npm start
```

5. Open http://localhost:3000 in your browser.

For local development, the server creates `users.sqlite` and `sessions.sqlite` in the project folder. Do not delete these files if you want to keep your local test accounts.

## Features
- Portfolio sections: Home, About, Projects, Account, Contact
- Responsive HTML/CSS layout
- Real registration and login endpoints
- Password hashes stored instead of plain-text passwords
- Server-side sessions with HTTP-only cookies
- Rate limiting for registration/login attempts
- Logout and current-session status
- Example protected API endpoint at `/api/private-example`

## Before public deployment
- Use HTTPS and set `NODE_ENV=production`.
- Set `SESSION_SECRET` to a securely generated random secret (at least 32 characters).
- Use persistent storage and a managed database appropriate for your hosting provider.
- Review security, backups, privacy notice, account recovery, email verification, and applicable privacy requirements.
- The site is provided as source code; it has not been publicly deployed by this package.
