"""CYBERWATCH-BD configuration.

Fail-closed secret contract:
- production (CWB_ENV=production): every secret MUST come from env; missing = boot halt.
- lab (default): secrets are generated once into data/secrets.json (0600) and loudly
  attested in the boot sequence. Warrants, RBAC and the audit chain stay fail-closed
  in every mode. Lab only, the TOTP *step-up gate* may be relaxed
  (CWB_TOTP_ENFORCE=auto/off) so research work can proceed without an authenticator;
  production always requires and verifies the code.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
KEYS = DATA / "secrets.json"

_GENERATED_KEYS = (
    "jwt_secret",
    "audit_hmac_key",
    "field_enc_key",
    "report_signing_key",
    "envelope_hmac_key",
)


def _load_generated() -> dict[str, str]:
    if not KEYS.exists():
        DATA.mkdir(parents=True, exist_ok=True)
        generated = {k: secrets.token_hex(32) for k in _GENERATED_KEYS}
        KEYS.write_text(json.dumps(generated, indent=2))
        os.chmod(KEYS, stat.S_IRUSR | stat.S_IWUSR)
        return generated
    return json.loads(KEYS.read_text())


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CWB_", env_file=ROOT / ".env", extra="ignore")

    env: str = "lab"  # lab | production
    version: str = "5.0"
    host: str = "0.0.0.0"
    port: int = 8000
    database_path: str = str(DATA / "cwb.db")
    reports_dir: str = str(DATA / "reports")
    uploads_dir: str = str(DATA / "uploads")
    mongo_uri: str = ""
    cors_origins: str = "http://localhost:3000,https://cyberwatch.vercel.app"
    rate_limit_default: str = "100/minute"
    rate_limit_login: str = "5/minute"
    access_token_ttl_min: int = 15
    refresh_token_ttl_days: int = 7
    replay_window_s: int = 300
    # TOTP step-up: auto = enforce in production, skip prompt in lab; on/off force it.
    totp_enforce: str = "auto"
    # external intel
    hibp_api_key: str = ""
    shodan_api_key: str = ""
    nvd_api_key: str = ""
    # soc / suricata
    suricata_eve_path: str = ""
    suricata_rules_path: str = ""
    block_agent_script: str = ""  # host agent that applies iptables rules
    # tor / ip anonymizer
    tor_control_host: str = "127.0.0.1"
    tor_control_port: int = 9051
    tor_control_password: str = ""
    proxychains_bin: str = "proxychains4"
    # compliance
    policy_hash_constant: str = ""  # immutable expected sha256 of the rulepack
    # secrets — production must inject these; lab generates them
    jwt_secret: str = ""
    audit_hmac_key: str = ""
    field_enc_key: str = ""
    report_signing_key: str = ""
    envelope_hmac_key: str = ""

    @property
    def is_production(self) -> bool:
        return self.env.strip().lower() == "production"

    @property
    def totp_stepup_required(self) -> bool:
        # Production can never relax the gate; only lab honors auto/off.
        mode = self.totp_enforce.strip().lower()
        return self.is_production or mode == "on"

    @property
    def origins(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def resolved(self) -> "Settings":
        missing = [k for k in _GENERATED_KEYS if not getattr(self, k)]
        if missing:
            if self.is_production:
                raise RuntimeError(
                    "fail-closed: production env requires secrets from env: " + ", ".join(missing)
                )
            gen = _load_generated()
            for k in missing:
                object.__setattr__(self, k, gen[k])
        weak = "change-me" in (self.jwt_secret, self.audit_hmac_key)
        if weak and self.is_production:
            raise RuntimeError("fail-closed: placeholder secret in production")
        return self


@lru_cache
def get_settings() -> Settings:
    s = Settings().resolved()
    for d in (s.reports_dir, s.uploads_dir, DATA):
        Path(d).mkdir(parents=True, exist_ok=True)
    return s
