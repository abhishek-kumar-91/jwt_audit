import re
from pathlib import Path

from .models import Finding


# ============================================================
# Helpers
# ============================================================

def make_finding(
    file,
    line,
    language,
    library,
    operation,
    evidence,
    rule_id,
    title,
    severity,
    status,
    confidence,
    remediation,
):
    metadata = {
        "JWT-001": (
            "Signature verification",
            "CWE-347",
            "A07:2021 Identification and Authentication Failures",
            "The source contains a JWT signing or verification flow that requires security review.",
            "If claims are trusted without complete verification, an attacker may forge identity or authorization claims.",
        ),
        "JWT-002": (
            "Algorithm validation",
            "CWE-327",
            "A02:2021 Cryptographic Failures",
            "JWT algorithm acceptance must be explicit and constrained to the application's trust model.",
            "An attacker may exploit an accepted algorithm or key-type mismatch to bypass signature validation.",
        ),
        "JWT-003": (
            "Unsigned tokens",
            "CWE-347",
            "A02:2021 Cryptographic Failures",
            "The implementation must reject unsigned JWTs for authenticated operations.",
            "An attacker could alter claims in a token using the none algorithm if it is accepted.",
        ),
        "JWT-004": (
            "Secret management",
            "CWE-798",
            "A07:2021 Identification and Authentication Failures",
            "Signing material should be supplied through protected runtime configuration or key management.",
            "A repository reader or compromised build artifact could recover the signing secret and forge tokens.",
        ),
        "JWT-005": (
            "Secret strength",
            "CWE-521",
            "A02:2021 Cryptographic Failures",
            "HMAC signing secrets must be sufficiently long and unpredictable.",
            "A weak secret may be guessed or brute-forced, enabling token forgery.",
        ),
        "JWT-006": (
            "Token lifetime",
            "CWE-613",
            "A07:2021 Identification and Authentication Failures",
            "Authentication tokens should have bounded lifetimes appropriate to their purpose.",
            "A stolen token may remain usable for an excessive period when expiration is absent or ineffective.",
        ),
        "JWT-007": (
            "Issuer validation",
            "CWE-287",
            "A07:2021 Identification and Authentication Failures",
            "Validate the expected issuer when multiple token issuers or trust domains exist.",
            "A token from an unintended issuer could be accepted as an application credential.",
        ),
        "JWT-008": (
            "Audience validation",
            "CWE-287",
            "A07:2021 Identification and Authentication Failures",
            "Validate the expected audience when tokens are intended for distinct services.",
            "A token issued for another service could be replayed against this service.",
        ),
        "JWT-009": (
            "Unverified parsing",
            "CWE-347",
            "A07:2021 Identification and Authentication Failures",
            "Decoded JWT claims must not cross a security trust boundary before cryptographic validation.",
            "An attacker may modify an unverified role, subject, or permission claim before authorization.",
        ),
        "JWT-010": (
            "Verification failure handling",
            "CWE-287",
            "A07:2021 Identification and Authentication Failures",
            "Malformed, expired, or unverifiable tokens must fail closed and reject the request.",
            "Swallowed verification errors or authenticated fallbacks can turn invalid credentials into access.",
        ),
    }.get(rule_id, ("JWT security", "", "", "JWT security behavior requires review.", "Improper JWT handling may weaken authentication or authorization."))
    category, cwe, owasp, explanation, attack_scenario = metadata
    return Finding(
        file=file,
        line=line,
        language=language,
        library=library,
        operation=operation,
        evidence=evidence,
        rule_id=rule_id,
        title=title,
        severity=severity,
        status=status,
        confidence=confidence,
        remediation=remediation,
        category=category,
        cwe=cwe,
        owasp=owasp,
        explanation=explanation,
        attack_scenario=attack_scenario,
        data_flow=f"{file}:{line} -> {operation} -> JWT security boundary",
    )


def match_line(content: str, pattern: str, flags=re.IGNORECASE) -> int:
    """
    Return the source-code line where pattern was found.
    Returns 1 if nothing is found.
    """
    match = re.search(pattern, content, flags)

    if not match:
        return 1

    return content[:match.start()].count("\n") + 1


def first_match(content: str, patterns, flags=re.IGNORECASE):
    """
    Return the first regex match from a list of patterns.
    """
    for pattern in patterns:
        match = re.search(pattern, content, flags)
        if match:
            return match

    return None


def is_java_jjwt(language, library):
    return language == "Java" and library == "JJWT"


def is_python_jwt(language, library):
    return (
        language == "Python"
        and library in {
            "PyJWT",
            "python-jose",
            "Authlib",
        }
    )


def is_javascript_jwt(language, library):
    return (
        language in {
            "JavaScript",
            "JavaScript/TypeScript",
        }
        and library in {
            "jsonwebtoken",
            "jose",
        }
    )


# ============================================================
# JWT-001
# Signature Verification / Signing
# ============================================================

def check_signature_verification(
    path,
    content,
    language,
    library,
    operation,
):

    # --------------------------------------------------------
    # Java / JJWT
    # --------------------------------------------------------

    if is_java_jjwt(language, library):

        builder = re.search(
            r"\bJwts\.builder\s*\(",
            content,
            re.IGNORECASE,
        )

        sign_with = re.search(
            r"\bsignWith\s*\(",
            content,
            re.IGNORECASE,
        )

        if builder and not sign_with:
            line = content[:builder.start()].count("\n") + 1

            return make_finding(
                file=str(path),
                line=line,
                language=language,
                library=library,
                operation="create/sign",
                evidence="Jwts.builder() detected without signWith()",
                rule_id="JWT-001",
                title="JWT Signing Not Detected",
                severity="HIGH",
                status="FAIL",
                confidence="High",
                remediation=(
                    "Sign JWTs using a strong cryptographic key and "
                    "an explicitly approved signing algorithm."
                ),
            )

        verify_with = re.search(
            r"\bverifyWith\s*\(",
            content,
            re.IGNORECASE,
        )

        parse_signed = re.search(
            r"\bparse(?:SignedClaims|ClaimsJws|Claims)\s*\(",
            content,
            re.IGNORECASE,
        )

        if verify_with and parse_signed:
            line = content[:verify_with.start()].count("\n") + 1

            return make_finding(
                file=str(path),
                line=line,
                language=language,
                library=library,
                operation="parse/verify",
                evidence=(
                    "verifyWith() and signed JWT parsing detected"
                ),
                rule_id="JWT-001",
                title="JWT Signature Verification",
                severity="HIGH",
                status="PASS",
                confidence="High",
                remediation=(
                    "Continue verifying the JWT signature before "
                    "trusting security-sensitive claims."
                ),
            )

        return make_finding(
            file=str(path),
            line=match_line(
                content,
                r"\bJwts\.(builder|parser)"
            ),
            language=language,
            library=library,
            operation=operation,
            evidence="JWT signing/verification flow requires manual review",
            rule_id="JWT-001",
            title="JWT Signature Verification",
            severity="HIGH",
            status="REVIEW",
            confidence="Medium",
            remediation=(
                "Confirm that JWTs are cryptographically signed and "
                "verified before claims are trusted."
            ),
        )

    # --------------------------------------------------------
    # Python
    # --------------------------------------------------------

    if language == "Python":

        # PyJWT
        if library == "PyJWT":

            decode = re.search(
                r"\bjwt\.decode\s*\(",
                content,
                re.IGNORECASE,
            )

            encode = re.search(
                r"\bjwt\.encode\s*\(",
                content,
                re.IGNORECASE,
            )

            if decode:
                line = content[:decode.start()].count("\n") + 1

                return make_finding(
                    file=str(path),
                    line=line,
                    language=language,
                    library=library,
                    operation="decode",
                    evidence="jwt.decode() detected",
                    rule_id="JWT-001",
                    title="JWT Signature Verification",
                    severity="HIGH",
                    status="REVIEW",
                    confidence="Medium",
                    remediation=(
                        "Confirm that jwt.decode() performs signature "
                        "verification and does not disable verification."
                    ),
                )

            if encode:
                line = content[:encode.start()].count("\n") + 1

                return make_finding(
                    file=str(path),
                    line=line,
                    language=language,
                    library=library,
                    operation="encode",
                    evidence="jwt.encode() detected",
                    rule_id="JWT-001",
                    title="JWT Signing",
                    severity="HIGH",
                    status="REVIEW",
                    confidence="Medium",
                    remediation=(
                        "Confirm that tokens are signed using a strong "
                        "key and approved algorithm."
                    ),
                )

        # python-jose
        if library == "python-jose":

            decode = re.search(
                r"\bjwt\.decode\s*\(",
                content,
                re.IGNORECASE,
            )

            encode = re.search(
                r"\bjwt\.encode\s*\(",
                content,
                re.IGNORECASE,
            )

            if decode:
                line = content[:decode.start()].count("\n") + 1

                return make_finding(
                    file=str(path),
                    line=line,
                    language=language,
                    library=library,
                    operation="decode",
                    evidence="python-jose jwt.decode() detected",
                    rule_id="JWT-001",
                    title="JWT Signature Verification",
                    severity="HIGH",
                    status="REVIEW",
                    confidence="Medium",
                    remediation=(
                        "Confirm that JWT signature verification remains "
                        "enabled before claims are trusted."
                    ),
                )

            if encode:
                line = content[:encode.start()].count("\n") + 1

                return make_finding(
                    file=str(path),
                    line=line,
                    language=language,
                    library=library,
                    operation="encode",
                    evidence="python-jose jwt.encode() detected",
                    rule_id="JWT-001",
                    title="JWT Signing",
                    severity="HIGH",
                    status="REVIEW",
                    confidence="Medium",
                    remediation=(
                        "Use a strong signing key and explicitly approved "
                        "algorithm."
                    ),
                )

        # Authlib
        if library == "Authlib":

            match = re.search(
                r"\b(?:jwt|JsonWebToken)\.",
                content,
                re.IGNORECASE,
            )

            if match:
                line = content[:match.start()].count("\n") + 1

                return make_finding(
                    file=str(path),
                    line=line,
                    language=language,
                    library=library,
                    operation=operation,
                    evidence=match.group(0),
                    rule_id="JWT-001",
                    title="JWT Cryptographic Verification",
                    severity="HIGH",
                    status="REVIEW",
                    confidence="Low",
                    remediation=(
                        "Confirm that Authlib verifies JWT signatures "
                        "before security-sensitive claims are trusted."
                    ),
                )

    # --------------------------------------------------------
    # JavaScript / TypeScript
    # --------------------------------------------------------

    if is_javascript_jwt(language, library):

        if library == "jsonwebtoken":

            verify = re.search(
                r"\bjwt\.verify\s*\(",
                content,
                re.IGNORECASE,
            )

            decode = re.search(
                r"\bjwt\.decode\s*\(",
                content,
                re.IGNORECASE,
            )

            sign = re.search(
                r"\bjwt\.sign\s*\(",
                content,
                re.IGNORECASE,
            )

            if verify:
                line = content[:verify.start()].count("\n") + 1

                return make_finding(
                    file=str(path),
                    line=line,
                    language=language,
                    library=library,
                    operation="verify",
                    evidence="jwt.verify() detected",
                    rule_id="JWT-001",
                    title="JWT Signature Verification",
                    severity="HIGH",
                    status="PASS",
                    confidence="High",
                    remediation=(
                        "Continue verifying JWT signatures before "
                        "trusting security-sensitive claims."
                    ),
                )

            if decode:
                line = content[:decode.start()].count("\n") + 1

                return make_finding(
                    file=str(path),
                    line=line,
                    language=language,
                    library=library,
                    operation="decode",
                    evidence="jwt.decode() detected without visible verification",
                    rule_id="JWT-001",
                    title="JWT Signature Verification",
                    severity="HIGH",
                    status="REVIEW",
                    confidence="Medium",
                    remediation=(
                        "Confirm that decoded claims are verified "
                        "before being used for authentication or authorization."
                    ),
                )

            if sign:
                line = content[:sign.start()].count("\n") + 1

                return make_finding(
                    file=str(path),
                    line=line,
                    language=language,
                    library=library,
                    operation="sign",
                    evidence="jwt.sign() detected",
                    rule_id="JWT-001",
                    title="JWT Signing",
                    severity="HIGH",
                    status="REVIEW",
                    confidence="Medium",
                    remediation=(
                        "Confirm that JWTs are signed with a strong key "
                        "and approved algorithm."
                    ),
                )

        if library == "jose":

            verify = re.search(
                r"\bjwtVerify\s*\(",
                content,
                re.IGNORECASE,
            )

            decode = re.search(
                r"\bdecodeJwt\s*\(",
                content,
                re.IGNORECASE,
            )

            sign = re.search(
                r"\bnew\s+SignJWT\s*\(",
                content,
                re.IGNORECASE,
            )

            if verify:
                line = content[:verify.start()].count("\n") + 1

                return make_finding(
                    file=str(path),
                    line=line,
                    language=language,
                    library=library,
                    operation="verify",
                    evidence="jwtVerify() detected",
                    rule_id="JWT-001",
                    title="JWT Signature Verification",
                    severity="HIGH",
                    status="PASS",
                    confidence="High",
                    remediation=(
                        "Continue verifying JWT signatures before "
                        "trusting claims."
                    ),
                )

            if decode:
                line = content[:decode.start()].count("\n") + 1

                return make_finding(
                    file=str(path),
                    line=line,
                    language=language,
                    library=library,
                    operation="decode",
                    evidence="decodeJwt() detected",
                    rule_id="JWT-001",
                    title="JWT Signature Verification",
                    severity="HIGH",
                    status="REVIEW",
                    confidence="Medium",
                    remediation=(
                        "Do not trust decoded JWT claims until "
                        "cryptographic verification is completed."
                    ),
                )

            if sign:
                line = content[:sign.start()].count("\n") + 1

                return make_finding(
                    file=str(path),
                    line=line,
                    language=language,
                    library=library,
                    operation="sign",
                    evidence="SignJWT detected",
                    rule_id="JWT-001",
                    title="JWT Signing",
                    severity="HIGH",
                    status="REVIEW",
                    confidence="Medium",
                    remediation=(
                        "Confirm that JWTs use an approved algorithm "
                        "and protected signing key."
                    ),
                )

    return make_finding(
        file=str(path),
        line=match_line(content, r"\bjwt\b"),
        language=language,
        library=library,
        operation=operation,
        evidence="JWT cryptographic flow requires manual review",
        rule_id="JWT-001",
        title="JWT Signature Verification",
        severity="HIGH",
        status="REVIEW",
        confidence="Low",
        remediation=(
            "Confirm JWT signature generation and verification."
        ),
    )


# ============================================================
# JWT-002
# Algorithm Restriction
# ============================================================

def check_algorithm_allowlist(
    path,
    content,
    language,
    library,
    operation,
):

    # Java / JJWT
    if is_java_jjwt(language, library):

        patterns = [
            r"\bsignWith\s*\([^)]*SignatureAlgorithm\.",
            r"\bSignatureAlgorithm\.",
            r"\bJwts\.SIG\.",
            r"\bsetAllowedAlgorithms\s*\(",
            r"\ballowedAlgorithms\s*\(",
        ]

        match = first_match(content, patterns)

        if match:
            line = content[:match.start()].count("\n") + 1

            return make_finding(
                file=str(path),
                line=line,
                language=language,
                library=library,
                operation=operation,
                evidence=match.group(0),
                rule_id="JWT-002",
                title="JWT Algorithm Restriction",
                severity="HIGH",
                status="PASS",
                confidence="High",
                remediation=(
                    "Keep JWT algorithms explicitly restricted to "
                    "approved algorithms."
                ),
            )

        return make_finding(
            file=str(path),
            line=match_line(
                content,
                r"\bJwts\.builder\s*\("
            ),
            language=language,
            library=library,
            operation=operation,
            evidence="No explicit JJWT algorithm configuration detected",
            rule_id="JWT-002",
            title="JWT Algorithm Restriction",
            severity="HIGH",
            status="REVIEW",
            confidence="Medium",
            remediation=(
                "Explicitly configure the intended signing algorithm "
                "and ensure verification accepts only approved algorithms."
            ),
        )

    # Python
    if language == "Python":

        patterns = [
            r"\balgorithms\s*=\s*\[[^\]]+\]",
            r"\balgorithms\s*=\s*\([^)]+\)",
            r"\balgorithms\s*=\s*[\"'][^\"']+[\"']",
            r"\balgorithm\s*=\s*[\"'][A-Za-z0-9_-]+[\"']",
            r"\balgorithms\s*[:=]",
            r"\ballowed_algs\b",
        ]

        match = first_match(content, patterns)

        if match:
            line = content[:match.start()].count("\n") + 1

            return make_finding(
                file=str(path),
                line=line,
                language=language,
                library=library,
                operation=operation,
                evidence=match.group(0),
                rule_id="JWT-002",
                title="JWT Algorithm Restriction",
                severity="HIGH",
                status="PASS",
                confidence="Medium",
                remediation=(
                    "Allow only the JWT algorithms required by "
                    "the application."
                ),
            )

        return make_finding(
            file=str(path),
            line=match_line(content, r"\bjwt\.(decode|encode)"),
            language=language,
            library=library,
            operation=operation,
            evidence="No explicit JWT algorithm restriction detected",
            rule_id="JWT-002",
            title="JWT Algorithm Restriction",
            severity="HIGH",
            status="REVIEW",
            confidence="Low",
            remediation=(
                "Configure an explicit allowlist of expected "
                "JWT signing algorithms."
            ),
        )

    # JavaScript / TypeScript
    if is_javascript_jwt(language, library):

        patterns = [
            r"\balgorithms\s*:\s*\[[^\]]+\]",
            r"\balgorithm\s*:\s*[\"'][^\"']+[\"']",
            r"\ballowedAlgorithms\b",
            r"\ballowed_algs\b",
        ]

        match = first_match(content, patterns)

        if match:
            line = content[:match.start()].count("\n") + 1

            return make_finding(
                file=str(path),
                line=line,
                language=language,
                library=library,
                operation=operation,
                evidence=match.group(0),
                rule_id="JWT-002",
                title="JWT Algorithm Restriction",
                severity="HIGH",
                status="PASS",
                confidence="Medium",
                remediation=(
                    "Allow only approved JWT algorithms."
                ),
            )

        return make_finding(
            file=str(path),
            line=match_line(
                content,
                r"\b(jwt\.(verify|sign)|jwtVerify)"
            ),
            language=language,
            library=library,
            operation=operation,
            evidence="No explicit JWT algorithm restriction detected",
            rule_id="JWT-002",
            title="JWT Algorithm Restriction",
            severity="HIGH",
            status="REVIEW",
            confidence="Low",
            remediation=(
                "Configure an explicit JWT algorithm allowlist."
            ),
        )

    return make_finding(
        file=str(path),
        line=1,
        language=language,
        library=library,
        operation=operation,
        evidence="Algorithm restriction requires manual review",
        rule_id="JWT-002",
        title="JWT Algorithm Restriction",
        severity="HIGH",
        status="REVIEW",
        confidence="Low",
        remediation=(
            "Ensure only approved JWT algorithms are accepted."
        ),
    )


# ============================================================
# JWT-003
# None / Unsigned Algorithm
# ============================================================

def check_none_algorithm(
    path,
    content,
    language,
    library,
    operation,
):

    patterns = [
        r'["\']none["\']',
        r'algorithm\s*[:=]\s*["\']none["\']',
        r'algorithms?\s*[:=]\s*\[[^\]]*["\']none["\']',
        r'algorithms?\s*=\s*\[[^\]]*["\']none["\']',
    ]

    match = first_match(content, patterns)

    if match:
        line = content[:match.start()].count("\n") + 1

        return make_finding(
            file=str(path),
            line=line,
            language=language,
            library=library,
            operation=operation,
            evidence="Unsigned/none JWT algorithm configuration detected",
            rule_id="JWT-003",
            title="Unsigned JWT / none Algorithm",
            severity="CRITICAL",
            status="FAIL",
            confidence="High",
            remediation=(
                "Reject unsigned JWTs and never allow the 'none' "
                "algorithm for authentication or authorization."
            ),
        )

    return make_finding(
        file=str(path),
        line=match_line(content, r"\bjwt\b"),
        language=language,
        library=library,
        operation=operation,
        evidence="No explicit none algorithm configuration detected",
        rule_id="JWT-003",
        title="Unsigned JWT / none Algorithm",
        severity="CRITICAL",
        status="PASS",
        confidence="Medium",
        remediation=(
            "Continue rejecting unsigned JWTs."
        ),
    )


# ============================================================
# JWT-004
# Hardcoded Secret / Key
# ============================================================

def check_hardcoded_secret(
    path,
    content,
    language,
    library,
    operation,
):

    patterns = []

    if language == "Java":

        patterns = [
            r'\bString\s+(?:SECRET|SECRET_KEY|JWT_SECRET|JWT_SECRET_KEY)\s*=\s*"[^"]+"',
            r'\b(?:SECRET|SECRET_KEY|JWT_SECRET|JWT_SECRET_KEY)\s*=\s*"[^"]+"',
            r'\bKeys\.hmacShaKeyFor\s*\(\s*"',
            r'\bsignWith\s*\(\s*"[^"]+"',
        ]

    elif language == "Python":

        patterns = [
            r'\b(?:SECRET|SECRET_KEY|JWT_SECRET|JWT_SECRET_KEY)\s*=\s*["\'][^"\']+["\']',
            r'\b(?:secret|key)\s*=\s*["\'][^"\']+["\']',
            r'\bSECRET_KEY\s*=\s*["\'][^"\']+["\']',
        ]

    elif is_javascript_jwt(language, library):

        patterns = [
            r'\b(?:SECRET|SECRET_KEY|JWT_SECRET|JWT_SECRET_KEY)\s*=\s*["\'][^"\']+["\']',
            r'\b(?:secret|secretKey|jwtSecret)\s*[:=]\s*["\'][^"\']+["\']',
            r'\bsecret\s*:\s*["\'][^"\']+["\']',
        ]

    match = first_match(content, patterns)

    if match:

        line = content[:match.start()].count("\n") + 1

        # Never print actual secret values.
        evidence = re.sub(
            r'(["\']).*?\1',
            r'\1***REDACTED***\1',
            match.group(0),
        )

        return make_finding(
            file=str(path),
            line=line,
            language=language,
            library=library,
            operation=operation,
            evidence=evidence,
            rule_id="JWT-004",
            title="Hardcoded JWT Secret/Key",
            severity="HIGH",
            status="FAIL",
            confidence="High",
            remediation=(
                "Move JWT secrets/private keys into protected runtime "
                "configuration or a dedicated secrets manager."
            ),
        )

    return make_finding(
        file=str(path),
        line=match_line(
            content,
            r"\b(jwt|Jwts|JWT)\b"
        ),
        language=language,
        library=library,
        operation=operation,
        evidence="No obvious hardcoded JWT secret detected",
        rule_id="JWT-004",
        title="Hardcoded JWT Secret/Key",
        severity="HIGH",
        status="PASS",
        confidence="Medium",
        remediation=(
            "Keep JWT cryptographic secrets outside source code."
        ),
    )


# ============================================================
# JWT-005
# Weak HMAC Secret
# ============================================================

def check_weak_secret(
    path,
    content,
    language,
    library,
    operation,
):

    patterns = [
        r'\b(?:secret|SECRET|SECRET_KEY|JWT_SECRET)\s*[:=]\s*["\'][^"\']{1,15}["\']',
        r'\b(?:key|KEY)\s*[:=]\s*["\'][^"\']{1,15}["\']',
        r'\bhmacShaKeyFor\s*\(\s*["\'][^"\']{1,31}["\']',
    ]

    match = first_match(content, patterns)

    if match:

        line = content[:match.start()].count("\n") + 1

        evidence = re.sub(
            r'(["\']).*?\1',
            r'\1***REDACTED***\1',
            match.group(0),
        )

        return make_finding(
            file=str(path),
            line=line,
            language=language,
            library=library,
            operation=operation,
            evidence=evidence,
            rule_id="JWT-005",
            title="Potential Weak JWT Secret",
            severity="HIGH",
            status="FAIL",
            confidence="Medium",
            remediation=(
                "Use a cryptographically strong, sufficiently long "
                "random signing secret."
            ),
        )

    return make_finding(
        file=str(path),
        line=match_line(content, r"\b(jwt|Jwts|JWT)\b"),
        language=language,
        library=library,
        operation=operation,
        evidence="No obviously weak JWT secret detected",
        rule_id="JWT-005",
        title="Weak JWT Secret",
        severity="HIGH",
        status="PASS",
        confidence="Low",
        remediation=(
            "Use a strong randomly generated JWT signing secret."
        ),
    )


# ============================================================
# JWT-006
# Expiration
# ============================================================

def check_expiration(
    path,
    content,
    language,
    library,
    operation,
):

    patterns = [
        r"\bexpiration\s*[:=]",
        r"\bexpiresIn\s*[:=]",
        r"\bexpires_in\s*[:=]",
        r"\bexp\s*[:=]",
        r"\.expiration\s*\(",
        r"\.setExpiration\s*\(",
        r"\bsetExpiration\s*\(",
        r"\bwithExpiresAt\s*\(",
        r"\bmaxAge\s*[:=]",
        r"\bttl\s*[:=]",
    ]

    match = first_match(content, patterns)

    if match:

        line = content[:match.start()].count("\n") + 1

        return make_finding(
            file=str(path),
            line=line,
            language=language,
            library=library,
            operation=operation,
            evidence=match.group(0),
            rule_id="JWT-006",
            title="JWT Expiration Handling",
            severity="MEDIUM",
            status="PASS",
            confidence="Medium",
            remediation=(
                "Keep JWT lifetimes bounded according to application "
                "risk and session requirements."
            ),
        )

    return make_finding(
        file=str(path),
        line=match_line(
            content,
            r"\b(jwt\.|Jwts\.|SignJWT|JWT)"
        ),
        language=language,
        library=library,
        operation=operation,
        evidence="No obvious JWT expiration configuration detected",
        rule_id="JWT-006",
        title="JWT Expiration Handling",
        severity="MEDIUM",
        status="REVIEW",
        confidence="Low",
        remediation=(
            "Confirm that authentication tokens have a bounded "
            "expiration time."
        ),
    )


# ============================================================
# JWT-007
# Issuer Validation
# ============================================================

def check_issuer(
    path,
    content,
    language,
    library,
    operation,
):

    patterns = [
        r"\bissuer\s*[:=]",
        r"\.issuer\s*\(",
        r"\.withIssuer\s*\(",
        r"\.setIssuer\s*\(",
        r"\bexpectedIssuer\b",
        r"\biss\b",
    ]

    match = first_match(content, patterns)

    if match:

        line = content[:match.start()].count("\n") + 1

        return make_finding(
            file=str(path),
            line=line,
            language=language,
            library=library,
            operation=operation,
            evidence=match.group(0),
            rule_id="JWT-007",
            title="JWT Issuer Validation",
            severity="MEDIUM",
            status="PASS",
            confidence="Medium",
            remediation=(
                "Validate the expected issuer when issuer validation "
                "is required by the application's trust model."
            ),
        )

    return make_finding(
        file=str(path),
        line=match_line(content, r"\b(jwt|Jwts|JWT)\b"),
        language=language,
        library=library,
        operation=operation,
        evidence="No explicit issuer validation detected",
        rule_id="JWT-007",
        title="JWT Issuer Validation",
        severity="MEDIUM",
        status="REVIEW",
        confidence="Low",
        remediation=(
            "Determine whether issuer validation is required and, "
            "if so, explicitly validate the expected issuer."
        ),
    )


# ============================================================
# JWT-008
# Audience Validation
# ============================================================

def check_audience(
    path,
    content,
    language,
    library,
    operation,
):

    patterns = [
        r"\baudience\s*[:=]",
        r"\.audience\s*\(",
        r"\.withAudience\s*\(",
        r"\.setAudience\s*\(",
        r"\bexpectedAudience\b",
        r"\baud\b",
    ]

    match = first_match(content, patterns)

    if match:

        line = content[:match.start()].count("\n") + 1

        return make_finding(
            file=str(path),
            line=line,
            language=language,
            library=library,
            operation=operation,
            evidence=match.group(0),
            rule_id="JWT-008",
            title="JWT Audience Validation",
            severity="MEDIUM",
            status="PASS",
            confidence="Medium",
            remediation=(
                "Validate the expected audience when the application's "
                "trust model requires audience restriction."
            ),
        )

    return make_finding(
        file=str(path),
        line=match_line(content, r"\b(jwt|Jwts|JWT)\b"),
        language=language,
        library=library,
        operation=operation,
        evidence="No explicit audience validation detected",
        rule_id="JWT-008",
        title="JWT Audience Validation",
        severity="MEDIUM",
        status="REVIEW",
        confidence="Low",
        remediation=(
            "Determine whether audience validation is required and, "
            "if so, explicitly validate the expected audience."
        ),
    )


# ============================================================
# JWT-009
# Unverified Decode / Parsing
# ============================================================

def check_unverified_decode(
    path,
    content,
    language,
    library,
    operation,
):

    # --------------------------------------------------------
    # Java / JJWT
    # --------------------------------------------------------

    if is_java_jjwt(language, library):

        patterns = [
            r"\bparseUnsecuredClaims\s*\(",
            r"\bparseUnsecuredContent\s*\(",
        ]

        match = first_match(content, patterns)

        if match:

            line = content[:match.start()].count("\n") + 1

            return make_finding(
                file=str(path),
                line=line,
                language=language,
                library=library,
                operation=operation,
                evidence=match.group(0),
                rule_id="JWT-009",
                title="Unverified JWT Parsing",
                severity="HIGH",
                status="FAIL",
                confidence="High",
                remediation=(
                    "Do not use unsecured or unverified JWT claims "
                    "for authentication or authorization decisions."
                ),
            )

        return make_finding(
            file=str(path),
            line=match_line(
                content,
                r"\bJwts\.(parser|builder)"
            ),
            language=language,
            library=library,
            operation=operation,
            evidence="No unsecured JJWT parsing method detected",
            rule_id="JWT-009",
            title="Unverified JWT Parsing",
            severity="HIGH",
            status="PASS",
            confidence="Medium",
            remediation=(
                "Ensure JWT claims are trusted only after "
                "successful cryptographic verification."
            ),
        )

    # --------------------------------------------------------
    # Python
    # --------------------------------------------------------

    if language == "Python":

        # PyJWT explicit verify_signature=False
        patterns = [
            r"jwt\.decode\s*\([^)]*verify_signature\s*=\s*False",
            r"jwt\.decode\s*\([^)]*options\s*=\s*\{[^}]*verify_signature[^}]*False",
        ]

        match = first_match(content, patterns)

        if match:

            line = content[:match.start()].count("\n") + 1

            return make_finding(
                file=str(path),
                line=line,
                language=language,
                library=library,
                operation="decode",
                evidence="JWT decode with signature verification disabled",
                rule_id="JWT-009",
                title="Unverified JWT Decode",
                severity="HIGH",
                status="FAIL",
                confidence="High",
                remediation=(
                    "Never disable JWT signature verification when "
                    "claims are used for authentication or authorization."
                ),
            )

        decode = re.search(
            r"\bjwt\.decode\s*\(",
            content,
            re.IGNORECASE,
        )

        if decode:

            line = content[:decode.start()].count("\n") + 1

            return make_finding(
                file=str(path),
                line=line,
                language=language,
                library=library,
                operation="decode",
                evidence="jwt.decode() requires verification-flow review",
                rule_id="JWT-009",
                title="Potential Unverified JWT Decode",
                severity="HIGH",
                status="REVIEW",
                confidence="Medium",
                remediation=(
                    "Confirm that decoded claims are never trusted "
                    "before signature verification."
                ),
            )

    # --------------------------------------------------------
    # JavaScript
    # --------------------------------------------------------

    if is_javascript_jwt(language, library):

        decode_patterns = [
            r"\bjwt\.decode\s*\(",
            r"\bdecodeJwt\s*\(",
        ]

        match = first_match(content, decode_patterns)

        if match:

            line = content[:match.start()].count("\n") + 1

            return make_finding(
                file=str(path),
                line=line,
                language=language,
                library=library,
                operation="decode",
                evidence=match.group(0),
                rule_id="JWT-009",
                title="Potential Unverified JWT Decode",
                severity="HIGH",
                status="REVIEW",
                confidence="Medium",
                remediation=(
                    "Do not use decoded JWT claims for security decisions "
                    "before cryptographic verification."
                ),
            )

    return make_finding(
        file=str(path),
        line=match_line(
            content,
            r"\b(jwt|Jwts|JWT)\b"
        ),
        language=language,
        library=library,
        operation=operation,
        evidence="No obvious unverified JWT decoding detected",
        rule_id="JWT-009",
        title="Unverified JWT Decode",
        severity="HIGH",
        status="PASS",
        confidence="Low",
        remediation=(
            "Ensure decoded JWT claims are never trusted before verification."
        ),
    )


# ============================================================
# JWT-010
# Verification Failure Handling
# ============================================================

def check_verification_failure_handling(
    path,
    content,
    language,
    library,
    operation,
):

    if language == "Java":

        patterns = [
            r"\bcatch\s*\([^)]*(?:JwtException|SecurityException)",
            r"\bcatch\s*\([^)]*Exception",
        ]

    elif language == "Python":

        patterns = [
            r"\bexcept\s+(?:jwt\.|JWT|InvalidTokenError|Exception)",
        ]

    else:

        patterns = [
            r"\bcatch\s*\([^)]*",
        ]

    match = first_match(content, patterns)

    if match:

        line = content[:match.start()].count("\n") + 1

        return make_finding(
            file=str(path),
            line=line,
            language=language,
            library=library,
            operation=operation,
            evidence=match.group(0),
            rule_id="JWT-010",
            title="JWT Verification Failure Handling",
            severity="MEDIUM",
            status="REVIEW",
            confidence="Medium",
            remediation=(
                "Ensure verification failures reject the request and "
                "cannot result in authentication or authorization bypass."
            ),
        )

    return make_finding(
        file=str(path),
        line=match_line(
            content,
            r"\b(jwt|Jwts|JWT)\b"
        ),
        language=language,
        library=library,
        operation=operation,
        evidence="JWT verification failure handling not clearly detected",
        rule_id="JWT-010",
        title="JWT Verification Failure Handling",
        severity="MEDIUM",
        status="REVIEW",
        confidence="Low",
        remediation=(
            "Confirm invalid or unverifiable JWTs are rejected safely."
        ),
    )


# ============================================================
# Main Rule Engine
# ============================================================

RULES = [
    check_signature_verification,
    check_algorithm_allowlist,
    check_none_algorithm,
    check_hardcoded_secret,
    check_weak_secret,
    check_expiration,
    check_issuer,
    check_audience,
    check_unverified_decode,
    check_verification_failure_handling,
]


def run_security_rules(
    path: Path,
    content: str,
    language: str,
    library: str,
    operation: str,
) -> list[Finding]:

    findings = []

    for rule in RULES:

        try:
            finding = rule(
                path=path,
                content=content,
                language=language,
                library=library,
                operation=operation,
            )

            if finding:
                findings.append(finding)

        except Exception as error:

            # Do not crash the entire scanner because one rule failed.
            findings.append(
                make_finding(
                    file=str(path),
                    line=1,
                    language=language,
                    library=library,
                    operation=operation,
                    evidence=f"Rule execution error: {error}",
                    rule_id="ENGINE-ERROR",
                    title="Security Rule Execution Error",
                    severity="LOW",
                    status="REVIEW",
                    confidence="Low",
                    remediation=(
                        "Review the rule implementation and rerun the scan."
                    ),
                )
            )

    return findings