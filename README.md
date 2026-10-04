# Web-Application-Security

## 1\. Web Application Security Assessment in the Context of Cybersecurity Projects

The cybersecurity project framework is structured around three foundational technical pillars[2]:

```
┌───────────────────────────────────────────────────────────┐
│              Cybersecurity Project Curriculum             │
├─────────────────────────────┬─────────────────────────────┤
│ 1. Secure Login System      │ Identity &amp; Authentication   │
│    (Preventive Controls)    │ (Argon2id, HttpOnly, Rate   │
│                             │  Limiting) [4]            │
├─────────────────────────────┼─────────────────────────────┤
│ 2. Web Application Security │ Offensive Auditing &amp;        │
│    Assessment (Audit &amp; Fix) │ Defensive Remediation       │
│                             │ (SQLi, XSS, BOLA) [1, 2] │
├─────────────────────────────┼─────────────────────────────┤
│ 3. Secure API Challenge     │ Application Hardening       │
│    (Defensive Architecture) │ (BOLA Defense, Pydantic     │
│                             │  DTOs, Error Shielding)[5]│
└─────────────────────────────┴─────────────────────────────┘

```

1. **Secure Login System (Authentication &amp; Identity)**: Focuses on **preventive credential handling**—implementing memory-hard hashing (Argon2id/bcrypt), `HttpOnly` cookie-based session management, and dual-key rate limiting to withstand brute-force attacks[4].
2. **Web Application Security Assessment (Vulnerability Analysis &amp; Remediation)**: Operates as an **end-to-end vulnerability cycle**. Developers transition from target reconnaissance and dynamic interception (via Burp Suite or OWASP ZAP) to ethical exploitation, root-cause code analysis, and permanent patch implementation[1].
3. **Secure API Challenge (API Security &amp; Hardening)**: Constructs **defensive RESTful backend architectures**, using schema validation (Pydantic/Zod) to prevent Mass Assignment and applying query-level checks to block Broken Object Level Authorization (BOLA)[5].

Within this larger ecosystem, **Web Application Security Assessment** tests whether runtime applications actually maintain their security promises under real-world threat conditions[1].

---

## 2\. Core Assessment Workflow &amp; Vulnerability Matrix

The assessment workflow follows four explicit stages[1][3]:

```
[ Target Reconnaissance ] ──► [ Vulnerability Exploitation ]
                                           │
                                           ▼
[ Regression Verification ] ◄── [ Source Code Remediation ]

```

1. **Reconnaissance &amp; Mapping**: Intercepting traffic with Burp Suite to map application surfaces, parameter inputs, and session mechanisms[3][12].
2. **Exploitation &amp; Proof-of-Concept (PoC)**: Safely proving vulnerabilities without causing database corruption or service denial[3].
3. **Root-Cause Code Analysis**: Inspecting source code to identify unsafe code sinks (e.g., dynamic string concatenation, unescaped HTML outputs)[3].
4. **Remediation &amp; Re-Testing**: Implementing secure code patterns and verifying that attack payloads are neutralized[3].

### Target Vulnerability Summary Matrix

| Vulnerability                                | OWASP Category                 | Root Cause                                                                             | Defense &amp; Mitigation Strategy                                                          |
| -------------------------------------------- | ------------------------------ | -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| **Auth Bypass SQL Injection (SQLi)**         | A03:2021-Injection             | Dynamic string concatenation in raw database queries[16].                            | **Parameterized Queries / Prepared Statements**[16][17].                           |
| **Stored Cross-Site Scripting (XSS)**        | A03:2021-Injection             | Rendering unsanitized dynamic user input into the browser DOM[16].                   | **Context-Aware HTML Output Escaping** / `html.escape()`[16].                        |
| **Broken Object Level Authorization (BOLA)** | A01:2021-Broken Access Control | Fetching records by URL parameter ID without verifying resource ownership[16][20]. | **Explicit Object-Level Ownership Verification** (`user_id == current_user.id`)[16]. |

---

## 3\. Code Breakdown &amp; Underlying Logic

The backend implementation (`app_remediated.py`) illustrates the exact technical transition from vulnerable constructs to secure code patterns[19][22].

### Module 1: SQL Injection (SQLi) Remediation Logic

```
# SECURE PATTERN: Parameterized Query prevents SQL Injection
@app.route('/api/login', methods=['POST'])
def secure_login():
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')

    db = get_db()
    cursor = db.cursor()

    # Prepared statement with parameter binding placeholders (?)
    query = "SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?"
    cursor.execute(query, (username, password))
    user = cursor.fetchone()

    if user:
        return jsonify({"status": "SUCCESS", "user": dict(user)}), 200
    return jsonify({"status": "FAILED", "message": "Invalid credentials"}), 401

```

* **Underlying Logic**: Parameterized queries enforce a strict structural boundary between **Executable SQL Logic** and **User-Supplied Data** at the database engine level[17][23].
* **Compilation Workflow**:
  1. *Prepare Phase*: The database engine compiles the SQL command template (`SELECT ... WHERE username = ? AND password_hash = ?`) into an Abstract Syntax Tree (AST) **before** looking at user parameters[24][25].
  2. *Execute Phase*: User strings are inserted directly into parameter slots. The database treats inputs strictly as **literal scalar values**, rendering quotes, semicolons, or inline SQL commands (`' OR '1'='1`) completely inert[17].

---

### Module 2: Stored Cross-Site Scripting (XSS) Remediation Logic

```
# SECURE PATTERN: Contextual Output Escaping / Input Sanitization
@app.route('/api/reviews', methods=['POST'])
def secure_add_review():
    data = request.get_json() or {}
    raw_review = data.get('review_text', '')
    user_id = data.get('user_id', 1)

    # HTML Escaping transforms special characters into safe HTML entities
    sanitized_review = html.escape(raw_review)

    db = get_db()
    cursor = db.cursor()
    cursor.execute("INSERT INTO reviews (user_id, review_text) VALUES (?, ?)", (user_id, sanitized_review))
    db.commit()

    return jsonify({"status": "SUCCESS", "review": sanitized_review}), 201

```

* **Underlying Logic**: Cross-Site Scripting occurs when an application stores executable client-side scripts (``) and renders them raw in another user's browser[12].
* **Sanitization Mechanism**: `html.escape()` parses input strings and converts reserved HTML control characters into neutral HTML entities (`&lt;` becomes `&lt;`, `&gt;` becomes `&gt;`, `&amp;` becomes `&amp;`, `"` becomes `"`)[19].
* **Browser Parsing Behavior**: When the browser encounters `&lt;script&gt;`, it renders the text literally as visible string characters on screen rather than instantiating an executable JavaScript DOM node[18][26].

---

## Impact Analysis: What Changes if Small Code Alterations Are Made?

Security controls are binary; minor modifications to secure code blocks immediately re-introduce high-severity security vulnerabilities[17].

```
┌───────────────────────────────────────┬───────────────────────────────────────┐
│ Code Modification                     │ Resulting Security Impact             │
├───────────────────────────────────────┼───────────────────────────────────────┤
│ Replace parameter binding (?) with    │ Restores Authentication Bypass        │
│ Python f-strings / string formatting  │ SQL Injection (SQLi) [17, 19].        │
├───────────────────────────────────────┼───────────────────────────────────────┤
│ Omit `html.escape()` or render via    │ Re-introduces Stored Cross-Site       │
│ unescaped dynamic HTML templates      │ Scripting (XSS) [18, 19].             │
├───────────────────────────────────────┼───────────────────────────────────────┤
│ Remove `AND user_id = ?` from SQL or  │ Opens Broken Object Level             │
│ skip ownership validation checks      │ Authorization (BOLA/IDOR) [20, 29].   │
├───────────────────────────────────────┼───────────────────────────────────────┤
│ Switch password hashing from Argon2id │ Enables rapid GPU-based offline       │
│ or bcrypt to standard MD5 / SHA-256   │ dictionary attacks [6, 30].         │
├───────────────────────────────────────┼───────────────────────────────────────┤
│ Store JWT tokens in `localStorage`   │ Exposes session tokens to instant XSS │
│ instead of `HttpOnly` cookies         │ exfiltration [31, 32].               │
└───────────────────────────────────────┴───────────────────────────────────────┘

```

### 1\. SQL Injection Modification

* **Code Alteration**: Changing `cursor.execute("SELECT ... WHERE username = ? AND password_hash = ?", (username, password))` to string formatting:

```
# DANGEROUS MODIFICATION: Re-introducing string concatenation
query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password_hash = '{password}'"
cursor.execute(query)

```

* **Resulting Failure**: An attacker submits the username payload: `' OR '1'='1' --`. The resulting query compiled by the database becomes:

```
SELECT id, username, role FROM users WHERE username = '' OR '1'='1' --' AND password_hash = '...'

```

Because `'1'='1'` evaluates to `TRUE` and `--` comments out the password check, the database returns the first record (typically the `admin` user), allowing complete **Authentication Bypass without a password**[17][23].

---

### 2\. Stored XSS Modification

* **Code Alteration**: Removing the `html.escape()` wrapper prior to database insertion:

```
# DANGEROUS MODIFICATION: Storing raw user input
cursor.execute("INSERT INTO reviews (user_id, review_text) VALUES (?, ?)", (user_id, raw_review))

```

* **Resulting Failure**: An attacker posts a review containing an exfiltration payload:

```

```

The raw payload is stored in the `reviews` table[12][18]. Whenever any user or administrator views the reviews dashboard, their browser executes the script in their session context, **exfiltrating session cookies and compromising their account**

### . Credential &amp; Session Storage Modifications

* **Password Hashing Alteration**: Switching from `Argon2id` / `bcrypt` to `SHA-256`:
  * *Impact*: SHA-256 computes in nanoseconds. In an offline database breach, attackers using modern GPUs can compute **tens of billions of SHA-256 hashes per second**, cracking user passwords within hours[6][32]. `Argon2id` forces high memory utilization and CPU cost, choking GPU parallelization[6].
* **Token Storage Alteration**: Storing JWTs in browser `localStorage` instead of `HttpOnly` cookies:
  * *Impact*: `localStorage` is accessible to client-side JavaScript (`window.localStorage`)[30][31]. A single XSS vulnerability anywhere on the origin allows malicious scripts to extract and exfiltrate user session tokens instantly[30]. `HttpOnly` cookies instruct the browser engine to block client-side script access entirely


