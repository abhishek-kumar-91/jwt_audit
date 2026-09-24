# JWT-Audit

**JWT-Audit** is a lightweight static-analysis security tool for identifying **JSON Web Token (JWT) implementations and common JWT security configuration issues** in application source code.

It recursively scans supported source files, detects JWT libraries and operations, and evaluates security-relevant implementation patterns such as signature verification, algorithm restrictions, hardcoded secrets, token expiration, issuer/audience validation, and unsafe JWT decoding.

> **Current focus:** Java, Python, JavaScript, and TypeScript applications.

---

## Features

### Language Support

| Language   | JWT Libraries / Frameworks        |
| ---------- | --------------------------------- |
| Java       | JJWT, Nimbus JOSE, Auth0 Java JWT |
| Python     | PyJWT, python-jose, Authlib       |
| JavaScript | jsonwebtoken, jose                |
| TypeScript | jsonwebtoken, jose                |

### Security Checks

JWT-Audit currently checks for:

| ID      | Security Check                       | Severity |
| ------- | ------------------------------------ | -------- |
| JWT-001 | JWT Signature Signing / Verification | HIGH     |
| JWT-002 | JWT Algorithm Restriction            | HIGH     |
| JWT-003 | Unsigned JWT / `none` Algorithm      | CRITICAL |
| JWT-004 | Hardcoded JWT Secret / Key           | HIGH     |
| JWT-005 | Potential Weak JWT Secret            | HIGH     |
| JWT-006 | JWT Expiration Handling              | MEDIUM   |
| JWT-007 | JWT Issuer Validation                | MEDIUM   |
| JWT-008 | JWT Audience Validation              | MEDIUM   |
| JWT-009 | Unverified JWT Decode / Parsing      | HIGH     |
| JWT-010 | JWT Verification Failure Handling    | MEDIUM   |

The scanner distinguishes between:

* **FAIL** — insecure behavior is supported by identifiable source-code evidence.
* **PASS** — an expected security control/pattern was detected.
* **REVIEW** — static analysis cannot reliably determine the security state and manual verification is required.

---

# Why JWT-Audit?

JWT security problems are often caused not by the JWT standard itself, but by incorrect implementation or configuration.

For example:

```java
Jwts.builder()
    .subject(userId)
    .compact();
```

The application appears to be creating a JWT, but no visible signing operation is present.

JWT-Audit can identify this pattern and report:

```text
[HIGH] JWT-001 | JWT Signing Not Detected | FAIL
Evidence: Jwts.builder() detected without signWith()
```

The goal is to quickly answer:

> **Where is JWT implemented, what security controls are present, what appears to be missing, and where should I investigate first?**

---

# Installation

## Requirements

* Python 3.10+
* Git (optional)
* Source code you are authorized to analyze

Check Python:

```bash
python --version
```

or:

```bash
python3 --version
```

---

## Clone the Project

```bash
git clone <repository-url>
cd jwt-audit
```

---

## Create a Virtual Environment

### Windows

```powershell
python -m venv .venv
```

Activate it:

```powershell
.venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

Current dependency:

```text
rich>=13.0.0
```

---

# Project Structure

```text
jwt-audit/
│
├── requirements.txt
│
├── jwt_audit/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── scanner.py
│   ├── detector.py
│   ├── models.py
│   ├── rules.py
│   └── reporter.py
│
└── test-project/
    ├── java/
    │   └── jwtService.java
    │
    ├── python/
    │   └── auth.py
    │
    └── javascript/
        └── auth.js
```

### Component Responsibilities

| File          | Responsibility                                |
| ------------- | --------------------------------------------- |
| `cli.py`      | Command-line interface                        |
| `scanner.py`  | Recursive source-code discovery               |
| `detector.py` | Language, JWT library and operation detection |
| `models.py`   | Finding data model                            |
| `rules.py`    | JWT security analysis                         |
| `reporter.py` | Terminal reporting                            |
| `__main__.py` | Python module entry point                     |

---

# Basic Usage

Run:

```bash
python -m jwt_audit scan <project-path>
```

Example:

```bash
python -m jwt_audit scan ./test-project
```

Windows:

```powershell
python -m jwt_audit scan D:\projects\my-application
```

Linux/macOS:

```bash
python3 -m jwt_audit scan /home/user/projects/my-application
```

---

# Command Reference

## Show Help

```bash
python -m jwt_audit --help
```

Expected:

```text
usage: jwt-audit [-h] [--version] {scan} ...

JWT implementation detection and security auditing tool.

positional arguments:
  {scan}
    scan       Scan a source-code project

options:
  -h, --help
  --version
```

---

## Show Version

```bash
python -m jwt_audit --version
```

Example:

```text
JWT-Audit 0.1.0
```

---

## Scan a Project

```bash
python -m jwt_audit scan ./test-project
```

The scanner recursively searches the supplied directory.

---

# Example Scan

Suppose the project contains:

```java
package com.example.auth;

import io.jsonwebtoken.Jwts;

public class JwtService {

    public String createToken(String userId) {

        return Jwts.builder()
                .subject(userId)
                .compact();
    }

    public void verifyToken(String token) {

        Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token);
    }
}
```

Run:

```bash
python -m jwt_audit scan ./test-project
```

Example output:

```text
JWT-AUDIT | JWT Security Assessment
Target: D:\jwt-audit\test-project

JWT implementations detected: 1
Languages: Java (1)
Libraries: JJWT (1)

HIGH PRIORITY / SECURITY ISSUES

[HIGH] JWT-001 | JWT Signing Not Detected | FAIL | D:\jwt-audit\test-project\java\jwtService.java:9
    Evidence: Jwts.builder() detected without signWith()
    Remediation: Sign JWTs using a strong cryptographic key and an explicitly approved signing algorithm.

[HIGH] JWT-002 | JWT Algorithm Restriction | REVIEW | D:\jwt-audit\test-project\java\jwtService.java:9
    Evidence: No explicit JJWT algorithm configuration detected
    Remediation: Explicitly configure the intended signing algorithm and ensure verification accepts only approved algorithms.

MANUAL REVIEW REQUIRED

[MEDIUM] JWT-006 | JWT Expiration Handling | REVIEW | D:\jwt-audit\test-project\java\jwtService.java:9
    Evidence: No obvious JWT expiration configuration detected
    Remediation: Confirm that authentication tokens have a bounded expiration time.

[MEDIUM] JWT-007 | JWT Issuer Validation | REVIEW | D:\jwt-audit\test-project\java\jwtService.java:9
    Evidence: No explicit issuer validation detected
    Remediation: Determine whether issuer validation is required.

[MEDIUM] JWT-008 | JWT Audience Validation | REVIEW | D:\jwt-audit\test-project\java\jwtService.java:9
    Evidence: No explicit audience validation detected
    Remediation: Determine whether audience validation is required.

PASSED SECURITY CHECKS

[PASS] JWT-003 | Unsigned JWT / none Algorithm | D:\jwt-audit\test-project\java\jwtService.java:9
[PASS] JWT-004 | Hardcoded JWT Secret/Key | D:\jwt-audit\test-project\java\jwtService.java:9
[PASS] JWT-009 | Unverified JWT Decode | D:\jwt-audit\test-project\java\jwtService.java:9

SUMMARY

FAIL: 1 | REVIEW: 4 | PASS: 3
Critical/High confirmed findings: 1
```

---

# Understanding the Output

Each finding follows this structure:

```text
[SEVERITY] RULE-ID | TITLE | STATUS | FILE:LINE
```

Example:

```text
[HIGH] JWT-001 | JWT Signing Not Detected | FAIL | auth/JwtService.java:25
```

### Severity

| Severity | Meaning                                                |
| -------- | ------------------------------------------------------ |
| CRITICAL | Potentially severe JWT security weakness               |
| HIGH     | Important security control or implementation issue     |
| MEDIUM   | Security configuration/control requiring investigation |
| LOW      | Lower-impact observation                               |
| INFO     | Informational discovery                                |

### Status

#### FAIL

The scanner found source-code evidence supporting an insecure condition.

Example:

```text
[CRITICAL] JWT-003 | Unsigned JWT / none Algorithm | FAIL
```

#### PASS

The scanner found an expected security control.

Example:

```text
[PASS] JWT-001 | JWT Signature Verification
```

#### REVIEW

The scanner cannot safely prove the security state through the current static analysis.

Example:

```text
[HIGH] JWT-002 | JWT Algorithm Restriction | REVIEW
```

This does **not** automatically mean the application is vulnerable.

It means:

> Review the implementation manually.

---

# Supported JWT Patterns

## Java

### JJWT

Detection examples:

```java
import io.jsonwebtoken.Jwts;
```

```java
Jwts.builder()
```

```java
Jwts.parser()
```

```java
verifyWith(key)
```

```java
signWith(key)
```

```java
parseSignedClaims(token)
```

---

### Nimbus JOSE

Examples:

```java
import com.nimbusds.jwt.*;
```

```java
JWTParser.parse(token);
```

---

### Auth0 Java JWT

Examples:

```java
import com.auth0.jwt.*;
```

```java
JWT.create()
```

```java
JWT.require()
```

---

# Python

## PyJWT

Examples:

```python
import jwt
```

```python
jwt.encode(...)
```

```python
jwt.decode(...)
```

---

## python-jose

Examples:

```python
from jose import jwt
```

```python
jwt.encode(...)
```

```python
jwt.decode(...)
```

---

## Authlib

Examples:

```python
from authlib.jose import ...
```

---

# JavaScript / TypeScript

## jsonwebtoken

Examples:

```javascript
const jwt = require("jsonwebtoken");
```

```javascript
jwt.sign(...)
```

```javascript
jwt.verify(...)
```

```javascript
jwt.decode(...)
```

---

## jose

Examples:

```javascript
import { SignJWT } from "jose";
```

```javascript
jwtVerify(...)
```

```javascript
decodeJwt(...)
```

---

# Example Vulnerable Patterns

## 1. Missing JWT Signing

```java
Jwts.builder()
    .subject(userId)
    .compact();
```

Potential finding:

```text
[HIGH] JWT-001 | JWT Signing Not Detected | FAIL
```

---

## 2. Unverified PyJWT Decode

```python
jwt.decode(
    token,
    SECRET_KEY,
    options={"verify_signature": False}
)
```

Potential finding:

```text
[HIGH] JWT-009 | Unverified JWT Decode | FAIL
```

---

## 3. JavaScript Decode

```javascript
const data = jwt.decode(token);
```

JWT-Audit reports this as requiring review because static analysis cannot automatically determine whether the decoded claims are subsequently trusted.

```text
[HIGH] JWT-009 | Potential Unverified JWT Decode | REVIEW
```

---

## 4. Hardcoded Secret

```python
JWT_SECRET = "my-super-secret-key"
```

Potential finding:

```text
[HIGH] JWT-004 | Hardcoded JWT Secret/Key | FAIL
```

The actual secret is **not displayed** in the report.

Example:

```text
Evidence: JWT_SECRET = "***REDACTED***"
```

---

# Directories Excluded From Scanning

JWT-Audit automatically ignores common generated/vendor directories:

```text
.git
.svn
.hg
node_modules
venv
.venv
env
.env
__pycache__
target
build
dist
.idea
.vscode
coverage
```

This reduces unnecessary scanning of dependencies and generated files.

---

# Supported Source Files

Currently supported extensions:

```text
.py
.java
.js
.jsx
.ts
.tsx
```

---

# Security Analysis Philosophy

JWT-Audit intentionally separates three concepts:

```text
Detection
   ↓
Security Analysis
   ↓
Reporting
```

### Detection

Find:

```text
JWT library
JWT implementation
JWT operation
```

### Security Analysis

Evaluate:

```text
Signature
Algorithm
Secret
Expiration
Issuer
Audience
Decode
Failure handling
```

### Reporting

Present:

```text
Severity
Status
File
Line
Evidence
Remediation
```

This architecture makes it possible to add additional languages, JWT libraries, and security rules without rewriting the entire scanner.

---

# Static Analysis Limitations

JWT-Audit is currently a **pattern-based static-analysis tool**.

It does not yet provide complete:

* AST analysis
* Data-flow analysis
* Control-flow analysis
* Interprocedural analysis
* Framework-aware authentication tracing
* Runtime behavior analysis
* Secret-manager verification
* Complete authorization-flow analysis

For example:

```java
String key = secretManager.getKey();

Jwts.builder()
    .signWith(key);
```

JWT-Audit can identify:

```text
signWith(key)
```

but it cannot guarantee that:

```text
secretManager.getKey()
```

returns a secure key.

Therefore, `PASS` means:

> An expected security pattern was detected.

It does not mean:

> The complete application has been proven secure.

Similarly, `REVIEW` means that manual verification is required.

---

# False Positives / False Negatives

Because JWT-Audit currently uses static source patterns, false positives and false negatives are possible.

For example:

```python
jwt.decode(token, key, algorithms=["HS256"])
```

may be secure in one application and insecure in another depending on:

* How the key is obtained
* Where the claims are used
* Authentication architecture
* Authorization logic
* Token issuer
* Audience requirements
* Token lifetime
* Key management

JWT-Audit should therefore be used as an **assessment accelerator**, not as a replacement for manual security review.

---

# Recommended Security Review Workflow

For a penetration test or source-code review:

```text
1. Run JWT-Audit
       ↓
2. Identify JWT implementations
       ↓
3. Review CRITICAL/HIGH FAIL findings
       ↓
4. Review HIGH/MEDIUM REVIEW findings
       ↓
5. Trace JWT authentication flow
       ↓
6. Validate exploitability manually
       ↓
7. Confirm impact
       ↓
8. Prepare security report
```

The scanner helps prioritize where to start.

---

# Example Project for Testing

Create:

```text
test-project/
│
├── java/
│   └── JwtService.java
│
├── python/
│   └── auth.py
│
└── javascript/
    └── auth.js
```

Then run:

```bash
python -m jwt_audit scan ./test-project
```

This is useful for regression testing when new JWT rules are added.

---

# Development

Run the tool directly from the repository:

```bash
python -m jwt_audit scan ./test-project
```

Before adding a new security rule:

1. Create a vulnerable fixture.
2. Create a secure fixture.
3. Run JWT-Audit against both.
4. Confirm the vulnerable fixture produces the expected finding.
5. Confirm the secure fixture does not produce an incorrect `FAIL`.
6. Verify the reported line number.
7. Verify evidence does not expose secrets.
8. Verify remediation is actionable.

---

# Adding a New JWT Rule

Security rules are implemented in:

```text
jwt_audit/rules.py
```

A rule should:

1. Have a unique rule ID.
2. Detect a specific security condition.
3. Return `PASS`, `FAIL`, or `REVIEW`.
4. Report an accurate source line.
5. Provide evidence.
6. Provide remediation.
7. Avoid exposing sensitive values.
8. Avoid claiming vulnerability when static analysis cannot prove it.

Example:

```python
def check_example(
    path,
    content,
    language,
    library,
    operation,
):
    ...
```

Then add the function to:

```python
RULES = [
    ...
]
```

---

# Roadmap

## Current

* [x] Recursive source scanning
* [x] Java detection
* [x] Python detection
* [x] JavaScript detection
* [x] TypeScript detection
* [x] JWT library detection
* [x] JWT operation detection
* [x] Security rule engine
* [x] Severity classification
* [x] PASS / FAIL / REVIEW
* [x] Evidence
* [x] Remediation
* [x] Source line reporting

## Planned

### Static Analysis Improvements

* [ ] Python AST analysis
* [ ] Java AST analysis
* [ ] JavaScript/TypeScript AST analysis
* [ ] Data-flow analysis
* [ ] Control-flow analysis
* [ ] Cross-function JWT tracking
* [ ] Better secret detection
* [ ] Better key-management analysis

### JWT Security Checks

* [ ] Key strength analysis
* [ ] Key rotation detection
* [ ] JWKS configuration analysis
* [ ] JWK trust validation
* [ ] `kid` handling
* [ ] `jku` handling
* [ ] `x5u` handling
* [ ] Sensitive claim detection
* [ ] Token storage analysis
* [ ] Refresh-token security
* [ ] Token revocation
* [ ] Clock-skew configuration
* [ ] Critical claim handling

### Reporting

* [ ] JSON output
* [ ] Excel report
* [ ] HTML report
* [ ] SARIF output
* [ ] CI/CD integration
* [ ] GitHub Actions integration
* [ ] Severity-based exit codes
* [ ] Executive summary
* [ ] Finding deduplication

---

# CI/CD Integration

A future CI/CD workflow will allow commands such as:

```bash
python -m jwt_audit scan .
```

and fail the build when confirmed critical/high findings are detected.

Example future behavior:

```text
FAIL:
Critical: 1
High: 2
```

Exit code:

```text
1
```

A clean project could return:

```text
Critical: 0
High: 0
Medium: 0

Exit code: 0
```

---

# Responsible Use

JWT-Audit is intended for:

* Authorized source-code review
* Secure software development
* Penetration testing
* Vulnerability assessment
* Security research
* CI/CD security checks
* Educational purposes

Only scan source code that you are authorized to analyze.

JWT-Audit does not perform exploitation or attack the target application. It performs static analysis of source code.

---

# Contributing

Contributions are welcome.

When contributing a new JWT security check, include:

```text
Rule ID
Rule title
Severity
Detection logic
Evidence
Remediation
Vulnerable test case
Secure test case
```

Please avoid introducing rules that classify uncertain conditions as confirmed vulnerabilities.

---

# License

Add the project's license here.

Example:

```text
MIT License
```

If this project is not yet licensed, do not assume or advertise a license until one has been selected.

---

# Author

**Abhishek Kumar**

Cybersecurity Researcher / Security Analyst

---

# Disclaimer

JWT-Audit is a static-analysis security tool and should be used as part of a broader secure-development or security-assessment process.

A scanner result does not by itself establish exploitability or the absence of vulnerabilities. Findings should be validated against the application's actual authentication, authorization, key-management, and deployment architecture.

---

## Quick Start

```bash
git clone <repository-url>

cd jwt-audit

python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt

python -m jwt_audit --version

python -m jwt_audit scan ./test-project
```

**JWT-Audit — Find JWT implementations. Identify security gaps. Prioritize manual review.**
