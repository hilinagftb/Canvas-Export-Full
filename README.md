# Canvas Course Exporter (Vercel edition)

A private website that connects to your Canvas, lists every course, and exports
course content, people, grades, discussions and quiz results in bulk.

## How it works

- **Vercel (the server)** only does three short jobs:
  - checks the passcode
  - keeps your Canvas address and token in an encrypted cookie that page scripts can't read
  - passes read-only requests from your browser to Canvas
- **Your browser** does the actual exporting. It queues the courses, waits for Canvas to
  package them, builds the CSV files, and saves everything.
  - **Chrome or Edge:** files are saved straight into a folder you choose, sorted by term and course.
  - **Other browsers:** course packages download one by one, and people and records come as one .zip.

Keep the tab open while exports run. Closing it stops them.

**Your Canvas must be reachable from the internet.** Vercel's servers contact Canvas
directly. If your Canvas only works inside your office network or VPN, a Vercel
deployment can't reach it. Use the local version instead.

---

## Deploy to Vercel

### 1. Make a secret key

Run this on your Mac and copy the long string it prints:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 2. Put the code on GitHub

Create a new **private** GitHub repository and upload the contents of this folder:
`api/`, `vercel.json`, `requirements.txt`, `README.md` and `.gitignore`.

### 3. Import it into Vercel

1. Go to vercel.com, click **Add New… → Project**, and import the repository.
2. For **Framework Preset**, choose **Other**. Leave the build settings empty.
3. Open **Environment Variables** and add:

   | Name | Value |
   |---|---|
   | `SECRET_KEY` | the long string from step 1 |
   | `APP_PASSCODE` | `347890` (or any code you choose) |

4. Click **Deploy**. When it finishes, open the site address Vercel gives you.

### 4. (Recommended) Make the passcode lockout permanent

On Vercel, the app can run on several servers at once. Without shared storage, the
"5 wrong tries" counter is kept on each server separately. For a lockout that holds
everywhere, add a free Redis database:

1. In your Vercel project, go to **Storage** (or **Marketplace**), then **Upstash Redis**, then **Create** and connect it to this project.
2. Vercel adds the connection settings automatically (`KV_REST_API_URL` / `KV_REST_API_TOKEN`, or `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN`).
3. Redeploy.

Once Redis is connected, the lockout works like this:
- After 5 wrong tries from one address, that address is locked out for 15 minutes.
- After 100 wrong tries per hour across the whole site, every login pauses.

### Deploy from the terminal instead (optional)

```bash
npm install -g vercel
cd canvas-exporter-vercel
vercel                     # first deploy, answer the questions
vercel env add SECRET_KEY  # paste the key, choose Production
vercel env add APP_PASSCODE
vercel --prod
```

---

## Use it

1. Open the site and enter the passcode.
2. Enter your Canvas address (like `https://canvas.yourorg.edu`) and an admin access token.
   To make a token: in Canvas, go to **Account → Settings → New access token**.
3. Choose **Where to save**: a folder (Chrome or Edge) or downloads.
4. Select courses, pick what to export (or a preset), then click **Export N courses**.
5. Watch the **Exports** tab:
   - Filter by status or type.
   - Click a finished export to see its files, then **Preview** or **Download** them.
   - Use **Download records (.zip)** for all people and records in one file.
   - Use **Download manifest** for a list of every export with its status.

**View people** on any course shows everyone enrolled, with search, role filters and a CSV
download. It doesn't need an export.

### What you get per course

| Option | Files |
|---|---|
| Course package | `course.imscc`: re-import into any Canvas |
| Course files | `files.zip` |
| Quizzes for other systems | `quizzes_qti.zip` |
| People | `people/people.csv`, `sections.csv`, `groups.csv` |
| Grades and submissions | `grades/gradebook.csv`, `submissions.csv`, `submission_comments.csv`, `assignments.csv` |
| Discussions and announcements | `discussions/discussion_topics.csv`, `discussion_posts.csv`, `discussions_raw.json` |
| Quiz results | `quiz_results/quiz_results.csv` |

The **Export all users** button saves `_account_<id>/account_users.csv`.

### Large course packages

Vercel can only pass files up to about 4 MB through itself. For larger packages, the browser:
1. first tries to fetch the file straight from your Canvas file storage
2. if the storage doesn't allow that, lets the browser download it normally into your
   **Downloads** folder (the Exports tab says so)

If you want large packages saved into your chosen folder too, ask whoever runs your Canvas
file storage (usually an S3 bucket) to allow `GET` requests from your Vercel site address
(a CORS rule).

---

## Run it on your own computer instead

```bash
pip install -r requirements.txt
python3 api/index.py
```

Open http://127.0.0.1:5050. Everything works the same way.

## Security

- The passcode is checked on the server. It isn't stored in the page, and nothing loads before it is entered.
- An unlocked session lasts 8 hours. Use **Lock** (top right) when you're done.
- The Canvas token is encrypted with your `SECRET_KEY` in an HttpOnly, Secure, SameSite=Strict
  cookie. It expires after 8 hours and is never shown to page scripts.
- The server only allows read requests to Canvas, plus "start a course export". It can't
  change or delete anything in Canvas, and it only talks to the Canvas address you connected.
- Use an `https://` Canvas address. The deployed site refuses plain `http://`.
- A 6-digit code is basic protection. Keep the Vercel address private, use the Redis lockout,
  and change `APP_PASSCODE` if it's ever shared. For stronger protection, turn on Vercel's
  own **Deployment Protection** (Password Protection or Vercel Authentication) in the project settings.
- The exported files are student records. Store them on encrypted, access-controlled storage,
  and delete the Canvas token when the project ends.
