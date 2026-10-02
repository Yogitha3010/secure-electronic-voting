# Secure Electronic Voting Prototype

An MCA academic prototype for demonstrating a Flask application foundation and, in later stages, hybrid cryptography concepts. It is **not** a real-election system.

## Completed in this stage

- Flask application with SQLite and SQLAlchemy
- Secure, hash-only user password storage
- Voter registration and login/logout
- CSRF-protected forms and server-side validation
- Admin account creation through an interactive Flask command
- Admin dashboard for creating elections, adding candidates, and starting/stopping one election at a time
- Voter ballot flow with one-vote enforcement and AES-256-GCM encrypted ballot storage
- Multiple scheduled elections with isolated candidates, votes, and automatic aggregate result views
- Basic Bootstrap home page

## Structure

```text
Crypto Project/
├── app.py              # Flask app, routes, configuration, CLI commands
├── models.py           # SQLAlchemy User model
├── forms.py            # Validated CSRF-protected web forms
├── requirements.txt    # Python dependencies
├── .env.example        # Required environment-variable template
├── templates/          # Jinja/Bootstrap pages
├── static/css/         # Application styling
└── instance/           # Created when run; holds the SQLite database (ignored by Git)
```

## Run locally (PowerShell)

1. Install Python 3.11 or later from [python.org](https://www.python.org/downloads/). During installation select **Add Python to PATH**.
2. In this project folder, create and activate an isolated environment:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. Install the dependencies:

   ```powershell
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```

4. Generate a random secret and set it for the current PowerShell session:

   ```powershell
   $env:SECRET_KEY = python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

   Do not commit or hardcode the generated value. The application intentionally reads its secret from the environment rather than source code.

5. Create the initial admin interactively, then start the server:

   ```powershell
   python -m flask --app app create-admin
   python -m flask --app app generate-voting-aes-key
   python -m flask --app app generate-voting-rsa-keys
   python -m flask --app app run --debug
   ```

6. Open `http://127.0.0.1:5000` in a browser.

## Test this stage

1. Register a voter at `/register` using a username of 3-30 letters/numbers/underscores, a valid email address, and a password of at least 12 characters.
2. Sign in with either that username or email, then sign out.
3. Sign in with the admin credentials created by `create-admin`.
4. Try an invalid form input or a wrong password to confirm it is rejected.
5. Sign in as a voter while an election is active, choose a candidate, and cast one vote. A second vote attempt is blocked.

## Multiple elections and results

New installations include election schedule/status columns automatically. For an existing SQLite database, run `python -m flask --app app init-db` after updating the code. It safely adds nullable `status`, `start_at`, and `end_at` columns to the existing `elections` table; it does not recreate the database or remove data.

Create each election with its own schedule and candidates. A voter may vote once in every active election. The admin **Results** page automatically decrypts and aggregates only the selected election's `votes` records; it displays totals, percentages, and a Chart.js doughnut chart without displaying individual choices.

Run the automated tests with:

```powershell
python -m unittest discover -s tests -v
```

The SQLite database is created at `instance/secure_voting.db` after the first application start. Run `generate-voting-aes-key` once before accepting votes; it creates a persistent 32-byte AES-256 key at `instance/keys/voting_aes.key`, which is ignored by Git and never sent to a browser or stored in SQLite. Run `generate-voting-rsa-keys` once to create an encrypted RSA private key and public key beneath `instance/keys/`; the command prompts for a passphrase and never prints either key. Existing databases are preserved: the new `votes` table is added automatically by `db.create_all()`, while the earlier `encrypted_ballots` table is left untouched as legacy development data. Passwords are stored only as salted Werkzeug password hashes; neither plaintext passwords nor an application secret are present in the repository.

## RSA protection of the AES key

Each new vote uses AES-256-GCM to encrypt its candidate payload. The persistent AES key is then encrypted with the RSA public key using RSA-OAEP with SHA-256, and that Base64 value is stored in `votes.encrypted_aes_key`. The AES key itself is never stored in SQLite.

Before running a server that displays results, set the RSA passphrase for its current PowerShell session:

```powershell
$securePassphrase = Read-Host "RSA key passphrase" -AsSecureString
$passphrasePointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassphrase)
$env:VOTING_RSA_PASSPHRASE = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passphrasePointer)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passphrasePointer)
```

For an existing database, run `python -m flask --app app init-db`. It adds the nullable `encrypted_aes_key` column to `votes` without deleting data. AES-only ballots from before this update remain readable through the protected AES key; all new ballots use RSA-protected AES keys.
