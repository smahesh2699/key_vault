# KeyVault — API Credentials Vault & Automated Leak Detection Platform

KeyVault is a secure, responsive API key management vault and real-time leak monitoring platform. It allows developers to securely store and encrypt their service credentials (OpenAI, Google Gemini, Stripe, AWS, etc.), track detailed usage metrics (tokens, requests, and costs in Indian Rupees), and scan public repositories automatically to detect credential exposures.

---

## 🚀 Key Features

1. **Secure Storage at Rest**: Encrypts secret key values using `cryptography.fernet` symmetric encryption. Plaintext secrets are never indexed or logged.
2. **Safe Fingerprinting & Prefixes**: Generates SHA-256 key fingerprints to prevent duplicate storage, and extracts safe prefix identifiers (e.g., `sk-proj-openai-p...`) for dashboard display.
3. **Decryption Re-authentication**: To reveal a decrypted key secret in the UI, users must confirm their account password as a safeguard.
4. **Billing Plan Auto-Detection**: Automatically fetches and classifies keys into **Free** or **Paid** plans:
   - *OpenAI*: Probes chat completions with a 1-token request and parses rate-limit response headers (`x-ratelimit-limit-requests` and `x-ratelimit-limit-tokens`).
   - *Gemini*: Probes the model and detects plan quotas from 429 quota exhaustion detail strings.
   - *AWS/Stripe*: Auto-resolves as Paid.
5. **Real-time Leak Scanning Simulator**: Scans public code repositories (simulated search engine) using the safe key prefix. Immediately flags exposed credentials as `LEAKED`, archives threat locations in the Alerts Inbox, and shifts status back to `ACTIVE` once marked as resolved.
6. **Cost & Usage Analytics Dashboard**:
   - Dynamic dark theme charts powered by **Chart.js** (Key Status Distribution, Service Breakdown, Threat Timeline, and Token Trends).
   - Real-time estimated spend tracker converted to **Indian Rupees (₹)** based on provider blended token rates.
   - Request Density tracker (Avg. Tokens / Request).
7. **Mobile-Responsive Sidebar Navigation**: A modern dashboard sidebar that collapses into a sleek off-canvas slide-out drawer menu on mobile viewports.
8. **Auth & Safety checks**: Rate-limited logins (5 requests/minute per IP) and strict regex email format validations with async welcome email notifications on sign-up.

---

## 🛠️ Technology Stack

*   **Backend**: FastAPI, Python 3.13
*   **Database**: SQLite, SQLAlchemy ORM, Alembic (Migrations)
*   **Frontend**: HTML5, Vanilla CSS3 (Custom Dark Theme Design System), JavaScript (AJAX, Modals, Toast notifications)
*   **Charts**: Chart.js (CDN)
*   **Testing**: Pytest & FastAPI TestClient

---

## ⚙️ Installation & Setup

### Prerequisites
*   Python 3.10+
*   Git

### Step 1: Clone the Repository
```bash
git clone <your-repository-url>
cd "API LEAK DETECTER"
```

### Step 2: Set up Virtual Environment
```bash
python -m venv .venv
# On Windows
.venv\Scripts\activate
# On macOS/Linux
source .venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Create a `.env` file in the root directory based on `.env.example`:
```ini
DATABASE_URL=sqlite:///./keyvault.db
SECRET_KEY=generate-a-secure-32-byte-hex-key-here
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# Email Settings (for registration welcomes)
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-email-app-password
MAIL_FROM=your-email@gmail.com
MAIL_PORT=587
MAIL_SERVER=smtp.gmail.com
```

### Step 5: Run Database Migrations
Initialize your local database schemas using Alembic:
```bash
alembic upgrade head
```

### Step 6: Start the Development Server
```bash
uvicorn app.main:app --reload
```
Open your browser and navigate to **[http://127.0.0.1:8000](http://127.0.0.1:8000)**.

---

## 🧪 Running Tests
Verify the complete platform security, CRUD actions, billing plan auto-detection, and leak simulator pipeline offline:
```bash
pytest
```
