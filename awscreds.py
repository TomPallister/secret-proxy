"""AWS credential vending for secret_proxy (Okta -> STS via saml2aws).

Ported from the standalone aws-auth container's server.py so secret_proxy can be the
single secret container. Owns the Okta secrets (fetched via a pluggable secret
provider) + the saml2aws session; mints short-lived STS creds per (account,
role), cached and serialized behind a login lock. Used by addon.py to re-sign
AWS SigV4 requests on the wire — the STS creds never leave the proxy.

Config (dict, from $SECRET_PROXY_CONFIG_DIR/aws-okta.json):
  region, session_duration, default_account, default_role,
  OKTA_USERNAME, OKTA_PASSWORD, OKTA_SECRET (canonical secret names),
  default_app_url,
  account_app_urls (per-account Okta SAML app overrides),
  allowed_roles (global role allow-list),
  account_role_overrides (per-account role allow-list overrides),
  operation_overrides (explicit per-role exceptions to the AWS operation
    deny list; see awsops.py and docs/operations.md)

Secrets are resolved via an injected ``get_secret(name) -> secret`` callable
(addon.py's resolver). Nothing is logged.
"""

from __future__ import annotations

import configparser
import datetime as dt
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Callable
from urllib.parse import urlsplit

from awsops import AwsPolicyError, parse_overrides

log = logging.getLogger("secret_proxy.awscreds")

OATHTOOL = "/usr/bin/oathtool"
SAML2AWS = "/usr/local/bin/saml2aws"
_PROVIDER_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/home/secretproxy",
    "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
}


def _base_subprocess_env() -> dict[str, str]:
    return _PROVIDER_ENV.copy()


DEFAULT_ACCOUNT_APP_URLS: dict[str, str] = {}
DEFAULT_ALLOWED_ROLES: list[str] = []
DEFAULT_ACCOUNT_ROLE_OVERRIDES: dict[str, list[str]] = {}

# IAM role names are distinct from IAM paths.  This is the character set and
# maximum length accepted for the role-name portion of a role ARN.
_IAM_ROLE_NAME_RE = re.compile(r"[A-Za-z0-9+=,.@_-]{1,64}\Z")
_ACCOUNT_ID_RE = re.compile(r"[0-9]{12}\Z")
_AWS_REGION_RE = re.compile(r"[a-z]{2}(?:-[a-z0-9]+){1,2}-[1-9][0-9]*\Z")
_OKTA_APP_PATH_RE = re.compile(r"/home/amazon_aws/[A-Za-z0-9]+/[0-9]+\Z")
_MIN_SESSION_DURATION = 900
_TOTP_STEP = 30
_MAX_SESSION_DURATION = 43200


class AwsCredsError(Exception):
    """A credential-vending failure.

    ``reason`` is a fixed, secret-free classification and ``kind`` drives the
    failure policy in get_creds (see _FAILURE_KINDS). Both are safe to log and
    to return to the container; the message is built only from fixed text,
    account ids and role names, never from provider output.
    """

    def __init__(self, message: str, *, reason: str = "invalid_config", kind: str = "config"):
        super().__init__(message)
        self.reason = reason
        self.kind = kind


# Failure kinds:
#   credentials  Okta rejected the identity itself (password, lockout, MFA).
#                Every further attempt with the same secrets counts towards
#                (or extends) an Okta lockout, so logins are suspended until
#                the OKTA_* secrets change or secret-proxy restarts.
#   target       Okta auth succeeded but this (account, role) could not be
#                vended. Only that target backs off.
#   transient    Anything else, including unrecognised saml2aws failures.
#                ALL logins back off exponentially: an unknown failure may be
#                an auth failure in a format we do not recognise.
#   suspended    Refused because logins are suspended; no Okta contact made.
#   backoff      Refused because a backoff is active; no Okta contact made.
#   config       Validation / policy failures; no Okta contact made.

# Ordered (reason, kind, stderr substrings, human hint). saml2aws prints a
# wrapped error chain on stderr, so the first match wins: lockout and MFA are
# checked before the primary-auth status, which also appears in some MFA chains.
_SAML2AWS_FAILURES: tuple[tuple[str, str, tuple[str, ...], str], ...] = (
    (
        "okta_locked_out", "credentials", ("the account is locked",),
        "Okta reports the account is locked",
    ),
    (
        "okta_mfa_rejected", "credentials", ("error verifying mfa",),
        "Okta rejected the TOTP code (wrong OKTA_SECRET seed, clock skew, or a reused code)",
    ),
    (
        "okta_credentials_rejected", "credentials",
        ("/api/v1/authn failed status: 401", "/api/v1/authn failed status: 403"),
        "Okta rejected the username/password (stale OKTA_PASSWORD, or the account is locked)",
    ),
    (
        "okta_rate_limited", "transient", ("status: 429",),
        "Okta rate-limited the login",
    ),
    (
        "aws_role_not_in_assertion", "target", ("failed to assume role",),
        "the Okta app's SAML assertion does not grant this role "
        "(wrong account_app_urls entry for the account, or no entitlement)",
    ),
    (
        "aws_sts_failed", "target", ("error retrieving sts credentials",),
        "STS AssumeRoleWithSAML failed (session_duration above the role maximum?)",
    ),
    (
        "saml_assertion_missing", "transient", ("did not contain a valid saml assertion",),
        "Okta returned no SAML assertion",
    ),
)


class AwsCredsProvider:
    @staticmethod
    def _validate_role_list(field: str, roles: object, account: str | None = None) -> None:
        subject = field if account is None else f"{field} for account {account}"
        if not isinstance(roles, list) or not roles:
            raise AwsCredsError(f"invalid {subject}: expected a non-empty list of IAM role names")
        if any(
            not isinstance(role, str) or _IAM_ROLE_NAME_RE.fullmatch(role) is None
            for role in roles
        ):
            raise AwsCredsError(f"invalid {subject}: expected a non-empty list of IAM role names")

    @staticmethod
    def _validate_app_url(field: str, value: object, account: str | None = None, *, hosts: list[str]) -> None:
        subject = field if account is None else f"{field} for account {account}"
        if not isinstance(value, str):
            raise AwsCredsError(f"invalid {subject}: expected an approved HTTPS Okta app URL")
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise AwsCredsError(
                f"invalid {subject}: expected an approved HTTPS Okta app URL"
            ) from exc
        if (
            parsed.scheme != "https"
            or parsed.hostname not in hosts
            or parsed.username is not None
            or parsed.password is not None
            or port is not None
            or parsed.query
            or parsed.fragment
            or _OKTA_APP_PATH_RE.fullmatch(parsed.path) is None
        ):
            raise AwsCredsError(f"invalid {subject}: expected an approved HTTPS Okta app URL")

    @classmethod
    def _validate_config(cls, config: object) -> None:
        if not isinstance(config, dict):
            raise AwsCredsError("invalid AWS credential configuration")

        hosts = config.get("okta_hosts")
        if not isinstance(hosts, list) or not hosts or any(
            not isinstance(h, str) or len(h) > 253
            or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+", h) is None
            for h in hosts
        ):
            raise AwsCredsError("okta_hosts must list exact approved DNS hosts")
        cls._validate_role_list("allowed_roles", config.get("allowed_roles"))

        for field in ("OKTA_USERNAME", "OKTA_PASSWORD", "OKTA_SECRET"):
            if config.get(field) != field:
                raise AwsCredsError(
                    f"Okta secret config {field} must use canonical name {field}"
                )

        if "app_url" in config:
            raise AwsCredsError("unsupported app_url: rename app_url to default_app_url")
        if "default_app_url" not in config:
            raise AwsCredsError("invalid default_app_url: an approved HTTPS Okta app URL is required")
        cls._validate_app_url("default_app_url", config["default_app_url"], hosts=hosts)

        app_urls = config.get("account_app_urls", {})
        if not isinstance(app_urls, dict):
            raise AwsCredsError("invalid account_app_urls: expected an object")
        for account, app_url in app_urls.items():
            if not isinstance(account, str) or _ACCOUNT_ID_RE.fullmatch(account) is None:
                raise AwsCredsError("invalid account_app_urls account key")
            cls._validate_app_url("account_app_urls", app_url, account, hosts=hosts)

        region = config.get("region", "eu-west-1")
        if not isinstance(region, str) or _AWS_REGION_RE.fullmatch(region) is None:
            raise AwsCredsError("invalid region: expected an AWS region name")

        duration = config.get("session_duration", "3600")
        if not isinstance(duration, str) or not duration.isascii() or not duration.isdecimal():
            raise AwsCredsError("invalid session_duration: expected seconds as a string")
        duration_seconds = int(duration)
        if not _MIN_SESSION_DURATION <= duration_seconds <= _MAX_SESSION_DURATION:
            raise AwsCredsError(
                f"invalid session_duration: expected {_MIN_SESSION_DURATION}..{_MAX_SESSION_DURATION} seconds"
            )

        default_account = config.get("default_account")
        if not isinstance(default_account, str) or _ACCOUNT_ID_RE.fullmatch(default_account) is None:
            raise AwsCredsError("invalid default_account: expected a 12-digit AWS account id")
        default_role = config.get("default_role")
        if not isinstance(default_role, str) or _IAM_ROLE_NAME_RE.fullmatch(default_role) is None:
            raise AwsCredsError("invalid default_role: expected an IAM role name")

        if "allowed_roles" in config:
            cls._validate_role_list("allowed_roles", config["allowed_roles"])

        if "operation_overrides" in config:
            # Explicit per-role exceptions to the AWS operation deny list.
            try:
                parse_overrides(config["operation_overrides"])
            except AwsPolicyError as exc:
                raise AwsCredsError(f"invalid {exc}") from None

        if "account_role_overrides" in config:
            overrides = config["account_role_overrides"]
            if not isinstance(overrides, dict):
                raise AwsCredsError("invalid account_role_overrides: expected an object")
            for account, roles in overrides.items():
                if not isinstance(account, str) or _ACCOUNT_ID_RE.fullmatch(account) is None:
                    raise AwsCredsError("invalid account_role_overrides account key")
                cls._validate_role_list("account_role_overrides", roles, account)

    def __init__(self, config: dict, get_secret: Callable[[str], str]):
        self._validate_config(config)
        self._cfg = config
        self._get_secret = get_secret
        self._lock = threading.Lock()
        self._cache: dict[tuple[str, str], tuple[dict, dt.datetime]] = {}
        self._skew = int(os.environ.get("AWS_AUTH_REFRESH_SKEW", "600"))
        self._duration = str(config.get("session_duration", "3600"))
        # Failure policy state, all guarded by self._lock in get_creds.
        self._backoff_base = int(os.environ.get("AWS_AUTH_FAILURE_BACKOFF_SECS", "60"))
        self._backoff_max = int(os.environ.get("AWS_AUTH_FAILURE_BACKOFF_MAX_SECS", "900"))
        self._fp_salt = os.urandom(16)
        self._suspended: tuple[bytes, str] | None = None  # (secrets fingerprint, reason)
        self._global_backoff: tuple[float, int, str] | None = None  # (until, failures, reason)
        self._target_backoff: dict[tuple[str, str], tuple[float, int, str]] = {}
        # Okta rejects a TOTP code that has already been used, and a rejected
        # code counts as a failed MFA attempt, so never reuse a time step.
        self._last_totp_step: int | None = None

    @classmethod
    def from_config_file(cls, path: str, get_secret: Callable[[str], str]) -> "AwsCredsProvider":
        with open(path) as f:
            return cls(json.load(f), get_secret)

    # --- TOTP ---------------------------------------------------------------
    def _wait_for_totp_window(self, min_buffer: int = 5) -> None:
        """Wait until the current TOTP step is unused and not about to roll over.

        Okta treats a replayed code as a failed MFA attempt, so a second login
        inside the same 30-second step (a different account, a retry) must
        wait for the next step instead of reusing the previous code.
        """
        while True:
            now = time.time()
            step = int(now // _TOTP_STEP)
            remaining = _TOTP_STEP - (now % _TOTP_STEP)
            if self._last_totp_step is not None and step <= self._last_totp_step:
                time.sleep(remaining + 0.5)
                continue
            if remaining < min_buffer:
                time.sleep(remaining + 0.5)
                continue
            return

    def _totp(self, seed: str) -> str:
        self._wait_for_totp_window()
        self._last_totp_step = int(time.time() // _TOTP_STEP)
        out = subprocess.run(
            [OATHTOOL, "--totp", "--base32", "-"],
            env=_base_subprocess_env(),
            input=seed + "\n",
            capture_output=True, text=True, timeout=15,
        )
        code = out.stdout.strip()
        if out.returncode != 0 or not code:
            raise AwsCredsError(
                f"oathtool failed (exit code {out.returncode})",
                reason="totp_generation_failed", kind="transient",
            )
        return code

    # --- creds file parsing -------------------------------------------------
    @staticmethod
    def parse_creds_file(path: str, profile: str = "saml") -> dict:
        cp = configparser.ConfigParser()
        cp.read(path)
        if profile not in cp:
            raise AwsCredsError(
                f"saml2aws wrote no [{profile}] profile to the creds file",
                reason="saml2aws_no_credentials", kind="transient",
            )
        s = cp[profile]
        ak = s.get("aws_access_key_id")
        sk = s.get("aws_secret_access_key")
        tok = s.get("aws_session_token") or s.get("aws_security_token")
        exp = s.get("x_security_token_expires")
        if not (ak and sk and tok):
            raise AwsCredsError(
                "saml2aws creds file missing key/secret/token",
                reason="saml2aws_no_credentials", kind="transient",
            )
        return {
            "AccessKeyId": ak,
            "SecretAccessKey": sk,
            "SessionToken": tok,
            "Expiration": exp or "",
        }

    def _parse_expiry(self, iso: str) -> dt.datetime:
        try:
            return dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=int(self._duration))

    # --- per-account app_url resolution -------------------------------------
    def _resolve_app_url(self, account: str) -> str:
        """Pick the Okta SAML app URL for a given account.

        Order: config account_app_urls[account] -> built-in default for account
        -> config default_app_url.
        """
        cfg = self._cfg
        # File's per-account overrides (may be empty/absent)
        file_overrides = cfg.get("account_app_urls", {})
        if account in file_overrides:
            return file_overrides[account]
        # Built-in defaults for known accounts
        if account in DEFAULT_ACCOUNT_APP_URLS:
            return DEFAULT_ACCOUNT_APP_URLS[account]
        return cfg["default_app_url"]

    # --- role allow-list ----------------------------------------------------
    @staticmethod
    def _validate_target(account: object, role: object) -> None:
        """Reject malformed account/role selectors before policy lookup or minting."""
        if not isinstance(account, str) or _ACCOUNT_ID_RE.fullmatch(account) is None:
            raise AwsCredsError("invalid AWS account id")
        if not isinstance(role, str) or _IAM_ROLE_NAME_RE.fullmatch(role) is None:
            raise AwsCredsError("invalid IAM role name")

    def _check_role_allowed(self, account: str, role: str) -> None:
        """Raise AwsCredsError if the role is not allowed for this account.

        Order: config account_role_overrides[account] -> built-in override for
        account -> config allowed_roles -> built-in DEFAULT_ALLOWED_ROLES.
        """
        self._validate_target(account, role)
        cfg = self._cfg
        # Per-account overrides from file
        file_acct_overrides = cfg.get("account_role_overrides", {})
        if account in file_acct_overrides:
            allowed = file_acct_overrides[account]
        elif account in DEFAULT_ACCOUNT_ROLE_OVERRIDES:
            # Built-in per-account override
            allowed = DEFAULT_ACCOUNT_ROLE_OVERRIDES[account]
        elif "allowed_roles" in cfg:
            # Global allow-list from file
            allowed = cfg["allowed_roles"]
        else:
            # Built-in global default
            allowed = DEFAULT_ALLOWED_ROLES
        if role not in allowed:
            raise AwsCredsError(f"role {role} not allowed for account {account}")

    # --- login --------------------------------------------------------------
    def _login(self, account: str, role: str) -> dict:
        cfg = self._cfg
        role_arn = f"arn:aws:iam::{account}:role/{role}"

        username_secret = cfg["OKTA_USERNAME"]
        password_secret = cfg["OKTA_PASSWORD"]
        totp_secret = cfg["OKTA_SECRET"]

        username = self._get_secret(username_secret)
        okta_pw = self._get_secret(password_secret)
        seed = self._get_secret(totp_secret)
        fingerprint = self._secrets_fingerprint(username, okta_pw, seed)
        if self._suspended is not None:
            if self._suspended[0] == fingerprint:
                username = okta_pw = seed = ""
                reason = self._suspended[1]
                raise AwsCredsError(
                    f"Okta logins suspended after {reason}: no further Okta attempts "
                    "are made with these credentials. Update the OKTA_* secrets, or "
                    "restart secret-proxy once the Okta account is unlocked",
                    reason=reason, kind="suspended",
                )
            log.warning("Okta credentials changed since the last rejection; resuming logins")
            self._suspended = None
        code = self._totp(seed)
        seed = ""

        # Resolve the Okta SAML app URL for this account
        app_url = self._resolve_app_url(account)
        if not app_url:
            raise AwsCredsError(f"no Okta app_url configured for account {account}")

        env = _base_subprocess_env()
        temp_dir = tempfile.mkdtemp(prefix="secret-proxy-s2a-")
        os.chmod(temp_dir, 0o700)
        creds_path = os.path.join(temp_dir, "credentials")
        fd = os.open(creds_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        env.update({
            "AWS_SHARED_CREDENTIALS_FILE": creds_path,
            "SAML2AWS_CONFIGFILE": os.environ.get("SECRET_PROXY_SAML_CONFIG", "/run/secret-proxy/saml2aws.ini"),
            "SAML2AWS_USERNAME": username,
            "SAML2AWS_PASSWORD": okta_pw,
            "SAML2AWS_MFA_TOKEN": code,
        })
        try:
            log.info(f"saml2aws login for {role_arn} (account {account})")
            try:
                proc = subprocess.run(
                    [
                        SAML2AWS, "login", "--force",
                        "--idp-account", "default",
                        "--idp-provider", "Okta",
                        "--mfa", "Auto",
                        "--url", app_url,
                        "--aws-urn", "urn:amazon:webservices",
                        "--region", cfg.get("region", "eu-west-1"),
                        "--role", role_arn,
                        "--session-duration", self._duration,
                        "--profile", "saml",
                        "--skip-prompt",
                    ],
                    env=env, capture_output=True, text=True, timeout=120,
                )
            except subprocess.TimeoutExpired:
                raise AwsCredsError(
                    f"saml2aws login for {role_arn} timed out",
                    reason="saml2aws_timeout", kind="transient",
                ) from None
            if proc.returncode != 0:
                reason, kind, hint = self.classify_saml2aws_failure(proc.stderr or "")
                if kind == "credentials":
                    self._suspended = (fingerprint, reason)
                log.warning(
                    "saml2aws login failed for %s: %s - %s (exit code %s)",
                    role_arn, reason, hint, proc.returncode,
                )
                raise AwsCredsError(
                    f"saml2aws login failed for {role_arn}: {reason} - {hint} "
                    f"(exit code {proc.returncode})",
                    reason=reason, kind=kind,
                )
            return self.parse_creds_file(creds_path)
        finally:
            # Drop Python references promptly and remove the private credentials
            # directory. A startup sweep removes stale crash remnants.
            username = okta_pw = code = ""
            shutil.rmtree(temp_dir, ignore_errors=True)

    # --- failure policy -----------------------------------------------------
    @staticmethod
    def classify_saml2aws_failure(stderr: str) -> tuple[str, str, str]:
        """Map saml2aws stderr to a fixed (reason, kind, hint).

        The raw stderr is never logged or returned: saml2aws error chains can
        embed request URLs carrying Okta session tokens.
        """
        low = stderr.lower()
        for reason, kind, needles, hint in _SAML2AWS_FAILURES:
            if any(n in low for n in needles):
                return reason, kind, hint
        return "saml2aws_failed", "transient", "unrecognised saml2aws failure"

    def _secrets_fingerprint(self, *values: str) -> bytes:
        h = hashlib.sha256(self._fp_salt)
        for v in values:
            h.update(b"\0" + v.encode())
        return h.digest()

    def _backoff_delay(self, failures: int) -> float:
        return float(min(self._backoff_base * (2 ** (failures - 1)), self._backoff_max))

    def _check_backoff(self, key: tuple[str, str]) -> None:
        now = time.monotonic()
        for scope, state in (("all logins", self._global_backoff),
                             (f"{key[0]}/{key[1]}", self._target_backoff.get(key))):
            if state is not None and now < state[0]:
                raise AwsCredsError(
                    f"AWS credential vending for {scope} is backing off for "
                    f"{int(state[0] - now) + 1}s after {state[2]}",
                    reason=state[2], kind="backoff",
                )

    def _record_failure(self, key: tuple[str, str], err: AwsCredsError) -> None:
        now = time.monotonic()
        if err.kind == "target":
            n = self._target_backoff.get(key, (0.0, 0, ""))[1] + 1
            self._target_backoff[key] = (now + self._backoff_delay(n), n, err.reason)
        elif err.kind == "transient":
            n = (self._global_backoff or (0.0, 0, ""))[1] + 1
            self._global_backoff = (now + self._backoff_delay(n), n, err.reason)

    def _record_success(self, key: tuple[str, str]) -> None:
        self._global_backoff = None
        self._target_backoff.pop(key, None)

    # --- public -------------------------------------------------------------
    def get_creds(self, account: str, role: str) -> dict:
        """Return cached STS creds for (account, role), refreshing via saml2aws
        when missing or within the refresh-skew of expiry.

        Raises AwsCredsError if the role is not in the allow-list for the account.
        """
        # Validate before doing anything (no mint for disallowed roles)
        self._check_role_allowed(account, role)

        key = (account, role)
        now = dt.datetime.now(dt.timezone.utc)
        hit = self._cache.get(key)
        if hit and (hit[1] - now).total_seconds() > self._skew:
            return hit[0]
        with self._lock:
            hit = self._cache.get(key)
            now = dt.datetime.now(dt.timezone.utc)
            if hit and (hit[1] - now).total_seconds() > self._skew:
                return hit[0]
            # Failed logins are never retried immediately: AWS SDKs retry 5xx,
            # and a script fanning out over accounts would otherwise turn one
            # bad password into a burst of Okta attempts and a lockout.
            self._check_backoff(key)
            try:
                creds = self._login(account, role)
            except AwsCredsError as err:
                self._record_failure(key, err)
                raise
            self._record_success(key)
            self._cache[key] = (creds, self._parse_expiry(creds["Expiration"]))
            return creds

    def default_target(self) -> tuple[str, str]:
        return (
            str(self._cfg.get("default_account", "")),
            str(self._cfg.get("default_role", "")),
        )


def _validate_config_cli(path: str) -> int:
    try:
        with open(path, encoding="utf-8") as config_file:
            config = json.load(config_file)
        AwsCredsProvider._validate_config(config)
    except AwsCredsError as exc:
        print(f"ERROR: invalid AWS/Okta configuration: {exc}", file=os.sys.stderr)
        return 2
    except (OSError, json.JSONDecodeError):
        print("ERROR: invalid AWS/Okta configuration", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    if len(os.sys.argv) != 3 or os.sys.argv[1] != "--validate-config":
        print("usage: awscreds.py --validate-config PATH", file=os.sys.stderr)
        raise SystemExit(2)
    raise SystemExit(_validate_config_cli(os.sys.argv[2]))
