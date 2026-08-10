# Local development authentication

The browser can use seeded local personas without an OIDC provider. This mode is rejected unless Django debug mode is enabled.

From PowerShell:

```powershell
cd C:\Users\satya\Trishul
$env:DEBUG="true"
$env:TRISHUL_DEV_AUTH="true"
$env:DJANGO_SECRET_KEY="local-development-only"

py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
cd backend
..\.venv\Scripts\python.exe manage.py migrate
..\.venv\Scripts\python.exe manage.py seed_dev
..\.venv\Scripts\python.exe manage.py runserver 127.0.0.1:8000
```

In a second PowerShell window:

```powershell
cd C:\Users\satya\Trishul\frontend
npm install
npm run dev
```

Open `http://localhost:5173` and choose a persona. The selector creates no shortcut around authorization: it supplies a seeded Django user identity, while the normal tenant membership, permission, RLS, engagement, workflow, assignment, separation-of-duties, and audit code continues to run.

`seed_dev` also loads the legally safe MVP reference pack: an ISO-like access-control requirement and a PCI-like password requirement share `UCO-DEV-IAM-001`; the latter adds the demonstration delta `password_minimum_length >= 12`. These records are explicitly marked as demonstration content with expert verification pending.

To run the complete automated local MVP journey (distinct control-owner, compliance-manager, auditor, audit-manager, CISO, and platform personas):

```powershell
cd C:\Users\satya\Trishul
.\.venv\Scripts\pytest.exe backend\core\tests\test_mvp_lifecycle.py -q
```

To return to production-style OIDC locally, stop the servers, set `TRISHUL_DEV_AUTH=false`, configure the existing OIDC variables, and restart. Production OIDC behavior is unchanged.
