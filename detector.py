import re
from pathlib import Path
from typing import List

from .models import Finding
from .rules import run_security_rules

LANGUAGES = {
    ".py": "Python",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "JavaScript/TypeScript",
    ".tsx": "JavaScript/TypeScript",
}


# JWT library signatures.
#This will grow significantly in later versions.

JWT_SIGNATURES = {

    # ========================================================
    # Python
    # ========================================================

    "Python": {

        "PyJWT": [
            "import jwt",
            "from jwt import",
            "jwt.encode(",
            "jwt.decode(",
        ],

        "python-jose": [
            "from jose import jwt",
            "from jose import",
            "jose.jwt",
        ],

        "Authlib": [
            "from authlib.jose import",
            "from authlib import jose",
            "authlib.jose",
        ],

        "Flask-JWT-Extended": [
            "flask_jwt_extended",
            "create_access_token(",
            "jwt_required(",
        ],

        "FastAPI JWT": [
            "fastapi_jwt_auth",
            "AuthJWT",
        ],
    },

    # ========================================================
    # Java
    # ========================================================

    "Java": {

        "JJWT": [
            "io.jsonwebtoken",
            "Jwts.",
            "JwtParser",
        ],

        "Nimbus JOSE": [
            "com.nimbusds.jwt",
            "NimbusJwtDecoder",
            "JWTParser",
        ],

        "Auth0 Java JWT": [
            "com.auth0.jwt",
            "JWT.create(",
            "JWT.require(",
        ],

        "Spring Security Nimbus": [
            "org.springframework.security.oauth2.jwt",
            "NimbusJwtDecoder",
            "JwtDecoder",
        ],
    },

    # ========================================================
    # JavaScript
    # ========================================================

    "JavaScript": {

        "jsonwebtoken": [
            "require('jsonwebtoken')",
            'require("jsonwebtoken")',
            "from 'jsonwebtoken'",
            'from "jsonwebtoken"',
            "jwt.sign(",
            "jwt.verify(",
            "jwt.decode(",
        ],

        "jose": [
            "from 'jose'",
            'from "jose"',
            "from 'jose/jwt'",
            'from "jose/jwt"',
            "SignJWT",
            "jwtVerify(",
            "decodeJwt(",
        ],

        "express-jwt": [
            "express-jwt",
            "expressjwt(",
        ],

        "koa-jwt": [
            "koa-jwt",
            "jwt({",
        ],
    },

    # ========================================================
    # TypeScript
    # ========================================================

    "JavaScript/TypeScript": {

        "jsonwebtoken": [
            "require('jsonwebtoken')",
            'require("jsonwebtoken")',
            "from 'jsonwebtoken'",
            'from "jsonwebtoken"',
            "jwt.sign(",
            "jwt.verify(",
            "jwt.decode(",
        ],

        "jose": [
            "from 'jose'",
            'from "jose"',
            "from 'jose/jwt'",
            'from "jose/jwt"',
            "SignJWT",
            "jwtVerify(",
            "decodeJwt(",
        ],

        "express-jwt": [
            "express-jwt",
            "expressjwt(",
        ],

        "koa-jwt": [
            "koa-jwt",
            "jwt({",
        ],
    },
}



OPERATION_PATTERNS = {

    "Python": [

        (
            r"\bjwt\.encode\s*\(",
            "encode",
        ),

        (
            r"\bjwt\.decode\s*\(",
            "decode",
        ),

        (
            r"\bcreate_access_token\s*\(",
            "create/sign",
        ),

        (
            r"\b(?:jwt_required|get_jwt|get_jwt_identity)\s*\(",
            "verify",
        ),

        (
            r"\bAuthJWT\s*\(",
            "verify",
        ),
    ],

    "Java": [

        (
            r"\bJwts\.builder\s*\(",
            "create/sign",
        ),

        (
            r"\bJwts\.parser\s*\(",
            "parse/verify",
        ),

        (
            r"\bJwts\.parserBuilder\s*\(",
            "parse/verify",
        ),

        (
            r"\bverifyWith\s*\(",
            "verify",
        ),

        (
            r"\bsignWith\s*\(",
            "sign",
        ),

        (
            r"\bparseClaimsJws\s*\(",
            "parse/verify",
        ),

        (
            r"\bparseSignedClaims\s*\(",
            "parse/verify",
        ),

        (
            r"\bJWT\.create\s*\(",
            "create/sign",
        ),

        (
            r"\bJWT\.require\s*\(",
            "verify",
        ),

        (
            r"\bJWTParser\.parse\s*\(",
            "parse",
        ),

        (
            r"\b(?:JwtDecoder|NimbusJwtDecoder)\b",
            "parse/verify",
        ),
    ],

    "JavaScript": [

        (
            r"\bjwt\.sign\s*\(",
            "sign",
        ),

        (
            r"\bjwt\.verify\s*\(",
            "verify",
        ),

        (
            r"\bjwt\.decode\s*\(",
            "decode",
        ),

        (
            r"\bjwtVerify\s*\(",
            "verify",
        ),

        (
            r"\bdecodeJwt\s*\(",
            "decode",
        ),

        (
            r"\bnew\s+SignJWT\s*\(",
            "create/sign",
        ),

        (
            r"\bexpressjwt\s*\(",
            "verify",
        ),

        (
            r"\bjwt\s*\(\s*\{",
            "verify",
        ),
    ],

    "JavaScript/TypeScript": [

        (
            r"\bjwt\.sign\s*\(",
            "sign",
        ),

        (
            r"\bjwt\.verify\s*\(",
            "verify",
        ),

        (
            r"\bjwt\.decode\s*\(",
            "decode",
        ),

        (
            r"\bjwtVerify\s*\(",
            "verify",
        ),

        (
            r"\bdecodeJwt\s*\(",
            "decode",
        ),

        (
            r"\bnew\s+SignJWT\s*\(",
            "create/sign",
        ),

        (
            r"\bexpressjwt\s*\(",
            "verify",
        ),

        (
            r"\bjwt\s*\(\s*\{",
            "verify",
        ),
    ],
}



def detect_language(path: Path) -> str | None:
    """
    Determine programming language from file extension.
    """

    return LANGUAGES.get(path.suffix.lower())


def detect_libraries(
    content: str,
    language: str
) -> list[str]:
    """
    Detect known JWT libraries used in a source file.
    """

    libraries = []

    signatures = JWT_SIGNATURES.get(language, {})

    for library, patterns in signatures.items():
        for pattern in patterns:
            if pattern in content:
                libraries.append(library)
                break

    return libraries


def detect_operations(
    content: str,
    language: str
) -> list[tuple[int, str, str]]:
    """
    Detect JWT operations.

    Returns:
        (line_number, operation, evidence)
    """

    results = []

    patterns = OPERATION_PATTERNS.get(language, [])

    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):

        for pattern, operation in patterns:

            if re.search(pattern, line):

                results.append(
                    (
                        line_number,
                        operation,
                        line.strip()
                    )
                )

    return results

def analyze_file(path: Path) -> List[Finding]:
    language = detect_language(path)

    if not language:
        return []

    try:
        content = path.read_text(
            encoding="utf-8",
            errors="ignore",
        )
    except Exception:
        return []

    libraries = detect_libraries(
        content,
        language,
    )

    if not libraries:
        return []

    operations = detect_operations(
        content,
        language,
    )

    if not operations:
        # A recognized JWT adapter can still be an implementation when its
        # API is configured through middleware or decorators.
        operations = [
            (
                1,
                "configuration",
                "JWT library configuration detected",
            )
        ]

    findings = []

    # --------------------------------------------------------
    # JWT discovery
    # --------------------------------------------------------

    for line_number, operation, evidence in operations:

        findings.append(
            Finding(
                file=str(path),
                line=line_number,
                language=language,
                library=libraries[0],
                operation=operation,
                evidence=evidence,
                rule_id="DISCOVERY",
                title="JWT Implementation Detected",
                severity="INFO",
                status="DETECTED",
                confidence="High",
            )
        )

    # --------------------------------------------------------
    # Security analysis
    # --------------------------------------------------------

    # Run security analysis once per file.
    #
    # The rule engine itself identifies whether the file contains
    # signing, verification, decode, etc.

    primary_operation = operations[0][1]

    security_findings = run_security_rules(
        path=path,
        content=content,
        language=language,
        library=libraries[0],
        operation=primary_operation,
    )

    findings.extend(security_findings)

    return findings
