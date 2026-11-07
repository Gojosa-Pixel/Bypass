"""Bypass engine: hardened async wrapper around the PyBypass library.

PyBypass facts this wrapper relies on (verified against PyBypass 2.0.1):

  * ``from PyBypass import bypass; bypass(url)`` -> direct URL (``str``)
  * auto-detection happens against ``PyBypass.Constants.regex.MAIN_REGEX``,
    a dict of {pattern: [name, function_name]} -- we reuse those patterns
    for *offline* link classification (no network round-trip).
  * typed exceptions: BypasserNotFoundError / UrlConnectionError /
    UnableToBypassError / RequiredValueNotFoundError.
  * all network calls are plain blocking ``requests`` without timeout and
    without a User-Agent -> fixed by the global session patch below, and by
    running every bypass in a bounded thread pool with an outer timeout.

Security note: PyBypass internally interpolates the URL into an ``eval()``
string. A URL containing a single quote could break out of that string, so
we hard-reject any URL containing quote-like characters before calling it.
(Our URL extractor already excludes them; this is belt and braces.)

v4: Cloudflare shield (services/cfshield.py) — every response PyBypass
fetches is inspected by the hardened session patch and recorded in CFWatch;
after a failed bypass the engine classifies the failure as "cloudflare"
when challenges were served. A per-domain circuit breaker fails fast while
a domain is cooling down, preventing the verification loop entirely.
Linkvertise ``?r=`` URLs resolve offline via services/resolvers.py, and
the adbypass.org fallback runs inside the same worker thread + timeout.
"""

import asyncio
import concurrent.futures
import logging
import re
import time

import requests

from services.cfshield import (
    CF_WATCH,
    DomainBreaker,
    backoff_seconds,
    host_of,
    is_cf_response,
)
from services.resolvers import (
    adbypass_resolve,
    linkvertise_fast_path,
    resolver_family,
)

log = logging.getLogger(__name__)

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------------
# Global requests hardening (applies to every request in this process,
# including the ones PyBypass makes with bare `requests.get(...)`).
#
# v4: responses are inspected for Cloudflare challenge markers and recorded
# in CFWatch — that's what lets the engine classify failures afterwards.
# ---------------------------------------------------------------------------
_original_session_request = requests.sessions.Session.request


def _hardened_session_request(self, method, url, **kwargs):
    kwargs.setdefault("timeout", 30)
    headers = kwargs.get("headers")
    if headers is None:
        headers = {}
        kwargs["headers"] = headers
    if isinstance(headers, dict) and not headers.get("User-Agent"):
        headers.setdefault("User-Agent", BROWSER_UA)
    response = _original_session_request(self, method, url, **kwargs)
    try:
        if is_cf_response(response):
            CF_WATCH.record(host_of(url or response.url or ""))
    except Exception:  # noqa: BLE001 — observation must never break a request
        pass
    return response


requests.sessions.Session.request = _hardened_session_request

# ---------------------------------------------------------------------------
# PyBypass import (after the patch, though order is irrelevant: the patch
# hooks the session *method*, which is looked up at call time).
# ---------------------------------------------------------------------------
try:  # pragma: no cover - import guard
    from PyBypass import bypass as _pybypass_call
    from PyBypass.Constants.regex import MAIN_REGEX
    from PyBypass.main import (
        BypasserNotFoundError,
        RequiredValueNotFoundError,
        UnableToBypassError,
        UrlConnectionError,
    )

    PYBYPASS_AVAILABLE = True
except Exception as _exc:  # pragma: no cover
    PYBYPASS_AVAILABLE = False
    MAIN_REGEX = {}
    _exc_repr = repr(_exc)

    class _Missing(Exception):
        pass

    BypasserNotFoundError = UrlConnectionError = (
        UnableToBypassError
    ) = RequiredValueNotFoundError = _Missing
    log.error("PyBypass could not be imported: %s", _exc_repr)

# URLs containing these characters can break PyBypass's internal eval();
# they are rejected before we ever hand the URL to the library.
_UNSAFE_URL_CHARS = ("'", '"', "\\", ";")


class BypassError(Exception):
    """Bypass failure with a machine-readable reason.

    reason is one of: unsupported, unreachable, failed, timeout,
    needs_credentials, unavailable, unsafe_url, cloudflare,
    cloudflare_cooldown, resolver_failed.
    """

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(detail or reason)


class BypassEngine:
    def __init__(self, timeout: float = 60.0, max_workers: int = 4,
                 api_resolvers: bool = True,
                 cf_breaker_threshold: int = 3,
                 cf_breaker_cooldown: float = 1800.0):
        self.timeout = timeout
        self.api_resolvers = api_resolvers
        self.breaker = DomainBreaker(
            threshold=cf_breaker_threshold,
            cooldown_seconds=cf_breaker_cooldown,
        )
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="bypass"
        )
        self._patterns: list = []
        if PYBYPASS_AVAILABLE:
            for pattern, value in MAIN_REGEX.items():
                try:
                    self._patterns.append((re.compile(pattern), value[0]))
                except re.error:
                    log.debug("skipping malformed PyBypass pattern: %r", pattern)

    # -------------------------- offline detection --------------------------

    def bypasser_name(self, url: str) -> str | None:
        """Name of the bypasser that would handle this URL, or None."""
        for pattern, name in self._patterns:
            if pattern.search(url):
                return name
        return None

    def is_bypassable(self, url: str) -> bool:
        if linkvertise_fast_path(url) is not None:
            return True
        return self.bypasser_name(url) is not None

    def supported_names(self) -> list:
        return sorted({name for _, name in self._patterns})

    # ---------------------------- actual bypass ----------------------------

    async def bypass(self, url: str) -> str:
        if not PYBYPASS_AVAILABLE:
            raise BypassError("unavailable", "PyBypass is not installed")
        if any(ch in url for ch in _UNSAFE_URL_CHARS):
            raise BypassError("unsafe_url", "URL contains forbidden characters")

        host = host_of(url)

        # Circuit breaker: fail fast while the domain cools down — this is
        # what actually prevents the Cloudflare verification *loop*.
        if self.breaker.is_blocked(host):
            status = self.breaker.status(host)
            raise BypassError(
                "cloudflare_cooldown",
                f"domain cooling down after repeated Cloudflare blocks "
                f"({status['streak']} in a row); retry in "
                f"{status['retry_in']:.0f}s",
            )

        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(self._executor, self._bypass_sync, url),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            cf_hit = CF_WATCH.seen(host)
            self.breaker.record(host, cf_hit)
            raise BypassError(
                "timeout", f"bypass took longer than {self.timeout:.0f}s"
            ) from None

    def _bypass_sync(self, url: str) -> str:
        """Blocking call into PyBypass. Runs inside a worker thread."""
        host = host_of(url)

        # 1) zero-network fast path (Linkvertise ?r= base64)
        fast = linkvertise_fast_path(url)
        if fast is not None:
            self.breaker.record(host, False)
            return fast

        # 2) PyBypass itself
        try:
            direct = _pybypass_call(url)
            self.breaker.record(host, False)
            return direct
        except (BypasserNotFoundError, UrlConnectionError,
                RequiredValueNotFoundError, UnableToBypassError) as exc:
            pybypass_error = exc
        except Exception as exc:  # noqa: BLE001 - PyBypass raises bare Exceptions
            pybypass_error = exc

        # 3) Cloudflare classification: did the hardened session patch see
        #    challenge responses for this host during the attempt above?
        cf_hit = CF_WATCH.seen(host)
        if cf_hit:
            self.breaker.record(host, True)
            raise BypassError(
                "cloudflare",
                "Cloudflare served a verification challenge; interactive "
                "turnstile cannot be solved from a server",
            ) from pybypass_error

        # 4) best-effort external resolver (adbypass.org) for the families
        #    the userscript ecosystem routes there (linkvertise hard case,
        #    admaven, lootlink). Runs behind the same outer timeout.
        if self.api_resolvers and resolver_family(url):
            resolved = adbypass_resolve(url)
            if resolved is not None:
                self.breaker.record(host, False)
                return resolved

        # 5) normal error path (unchanged semantics)
        if isinstance(pybypass_error, BypasserNotFoundError):
            raise BypassError(
                "unsupported", "no bypasser script for this shortener"
            ) from pybypass_error
        if isinstance(pybypass_error, UrlConnectionError):
            raise BypassError(
                "unreachable", "shortener unreachable / Cloudflare / non-200"
            ) from pybypass_error
        if isinstance(pybypass_error, RequiredValueNotFoundError):
            raise BypassError(
                "needs_credentials", str(pybypass_error)
            ) from pybypass_error
        raise BypassError(
            "failed", f"{type(pybypass_error).__name__}: {pybypass_error}"
        ) from pybypass_error

    # --------------------------- retry helper ------------------------------
    # convenience for our own fetches (health monitor etc.)

    @staticmethod
    def fetch_with_retry(get, url: str, attempts: int = 3):
        """GET with exponential backoff; returns the last response.

        ``get`` is a callable like ``requests.get`` (injected for tests).
        Aborts early when a Cloudflare challenge is detected — never
        hammers a challenge endpoint in a tight loop.
        """
        from services.cfshield import is_cf_challenge

        response = None
        for attempt in range(max(1, attempts)):
            response = get(url, timeout=30)
            if is_cf_challenge(response.status_code, response.headers,
                               response.text or ""):
                if attempt < attempts - 1:
                    time.sleep(backoff_seconds(attempt))
                    continue
            break
        return response
