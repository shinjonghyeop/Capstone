#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from os.path import join as path_join
from typing import Optional, Iterator, List, Tuple

from httpx import ReadTimeout, HTTPStatusError, RequestError

from wapitiCore.attack.attack import Attack, Parameter
from wapitiCore.language.vulnerability import Messages
from wapitiCore.definitions.crlf import CrlfFinding
from wapitiCore.definitions.resource_consumption import ResourceConsumptionFinding
from wapitiCore.model import PayloadInfo
from wapitiCore.net import Request, Response
from wapitiCore.main.log import logging, log_verbose, log_orange, log_red
from wapitiCore.parsers.txt_payload_parser import TxtPayloadReader


class ModuleCrlf(Attack):
    """Detect Carriage Return Line Feed (CRLF) injection vulnerabilities."""

    name = "crlf"
    MSG_VULN = "CRLF Injection"
    do_get = True
    do_post = True
    PAYLOADS_FILE = "crlfPayloads.txt"

    # ---------- Performance / Strategy knobs ----------
    # (1) Quick probe → Full scan
    QUICK_PAYLOAD_LIMIT = 5

    # (3) Header test reduction with prioritization
    HEADER_QUICK = ["User-Agent", "X-Forwarded-For", "Referer"]
    HEADER_FULL = [
        "User-Agent",
        "X-Forwarded-For",
        "Referer",
        "X-Forwarded-Host",
        "X-Original-URL",
        "X-Custom-Header",
    ]

    # If True, run FULL scan only when quick phase yields suspicious signals
    ENABLE_FULL_SCAN_ONLY_ON_SUSPICIOUS = True

    # (4) Payload dedupe strength (case-insensitive basic dedupe)
    PAYLOAD_DEDUPE_CASE_INSENSITIVE = True

    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        super().__init__(crawler, persister, attack_options, crawler_configuration)
        self.mutator = self.get_mutator()

        # Endpoint-level "already found" to skip redundant re-tests within same run
        self._reported_endpoint_vuln = set()

        # Header-only cache (retained for compatibility / speed)
        self._reported_header_vuln = set()

        # Cache payloads (deduped) to avoid re-reading the file for every request
        self._payloads_all: Optional[List[PayloadInfo]] = None
        self._payloads_quick: Optional[List[PayloadInfo]] = None

    # ---------------- Payload handling ----------------

    def _load_payloads_cached(self) -> List[PayloadInfo]:
        if self._payloads_all is not None:
            return self._payloads_all

        payload_reader = TxtPayloadReader(path_join(self.DATA_DIR, self.PAYLOADS_FILE))

        seen = set()
        deduped: List[PayloadInfo] = []

        for pinfo in payload_reader:
            raw = (pinfo.payload or "").strip()
            if not raw:
                continue

            key = raw.lower() if self.PAYLOAD_DEDUPE_CASE_INSENSITIVE else raw
            if key in seen:
                continue
            seen.add(key)
            deduped.append(pinfo)

        self._payloads_all = deduped
        return deduped

    def _get_quick_payloads(self) -> List[PayloadInfo]:
        if self._payloads_quick is not None:
            return self._payloads_quick

        all_payloads = self._load_payloads_cached()
        self._payloads_quick = all_payloads[: self.QUICK_PAYLOAD_LIMIT]
        return self._payloads_quick

    # Keep original signature (Wapiti expects it)
    def get_payloads(self, _: Optional[Request] = None, __: Optional[Parameter] = None) -> Iterator[PayloadInfo]:
        """Default: full (deduped) payloads."""
        yield from self._load_payloads_cached()

    def _iter_payloads(self, quick: bool, _: Optional[Request] = None, __: Optional[Parameter] = None) -> Iterator[PayloadInfo]:
        """Internal: select quick vs full payload stream."""
        if quick:
            yield from self._get_quick_payloads()
        else:
            yield from self._load_payloads_cached()

    # ---------------- Detection ----------------

    def _check_crlf_injection(self, response: Response) -> bool:
        """Detect CRLF injection evidence in response headers."""
        # 1) Header name contains marker
        for header_name in response.headers.keys():
            if "wapiti" in header_name.lower():
                return True

        # 2) Header value contains marker
        for header_value in response.headers.values():
            if "wapiti" in str(header_value).lower():
                return True

        return False

    def _is_suspicious(self, response: Optional[Response]) -> bool:
        """
        Heuristic used to decide whether to expand Quick → Full scan.
        Conservative by design: avoids running full scans everywhere.

        Signals:
        - 5xx responses
        - Common header parsing / CRLF-related error strings in the first 4KB of body
        """
        if response is None:
            return False

        try:
            status = getattr(response, "status_code", None)
            if isinstance(status, int) and status >= 500:
                return True
        except Exception:
            pass

        try:
            content = response.content
            if isinstance(content, bytes):
                body = content[:4096].decode("utf-8", errors="ignore").lower()
            else:
                body = str(content)[:4096].lower()

            for needle in (
                "invalid header",
                "bad request",
                "header name",
                "header value",
                "request header",
                "malformed",
                "illegal character",
                "newline",
                "crlf",
            ):
                if needle in body:
                    return True
        except Exception:
            return False

        return False

    # ---------------- Attack orchestration ----------------

    async def attack(self, request: Request, response: Optional[Response] = None):
        page = request.path
        endpoint_key = f"{request.method}:{request.path}"

        # Endpoint-wide global early exit
        if endpoint_key in self._reported_endpoint_vuln:
            log_verbose(f"[!] Skipping CRLF module for {endpoint_key} (already found)")
            return

        # Phase 1: QUICK probe across parameter + header
        found, suspicious = await self._scan_endpoint(request, page, quick=True)
        if found:
            self._reported_endpoint_vuln.add(endpoint_key)
            return

        # Decide whether to expand to FULL scan
        if self.ENABLE_FULL_SCAN_ONLY_ON_SUSPICIOUS and not suspicious:
            log_verbose(f"[!] CRLF quick probe not suspicious for {endpoint_key}, skipping full scan")
            return

        # Phase 2: FULL scan (deduped payloads, expanded header list)
        found, _ = await self._scan_endpoint(request, page, quick=False)
        if found:
            self._reported_endpoint_vuln.add(endpoint_key)

    async def _scan_endpoint(self, request: Request, page: str, quick: bool) -> Tuple[bool, bool]:
        """
        Execute a scan phase for a single endpoint (parameter + header only).
        Returns: (found, suspicious)
        """
        found_any = False
        suspicious_any = False

        # 1) Parameter mutation
        found, suspicious = await self._test_parameter_mutation(request, page, quick=quick)
        found_any |= found
        suspicious_any |= suspicious
        if found_any:
            return True, suspicious_any  # endpoint-wide early exit

        # 2) Header injection
        found, suspicious = await self._test_header_injection(request, quick=quick)
        found_any |= found
        suspicious_any |= suspicious
        if found_any:
            return True, suspicious_any  # endpoint-wide early exit

        return found_any, suspicious_any

    # ---------------- Injection point: parameters ----------------

    async def _test_parameter_mutation(self, request: Request, page: str, quick: bool) -> Tuple[bool, bool]:
        """
        Mutate parameters using quick/full payload stream.
        Breaks on first confirmed vuln (endpoint-wide early-exit behavior).
        Returns: (found, suspicious)
        """
        found = False
        suspicious = False

        payload_selector = (lambda r=None, p=None: self._iter_payloads(quick, r, p))

        for mutated_request, parameter, _payload in self.mutator.mutate(
            request,
            payload_selector,
        ):
            log_verbose(f"[¨] {mutated_request.url}")

            try:
                resp = await self.crawler.async_send(mutated_request)
            except ReadTimeout:
                self.network_errors += 1
                await self.add_medium(
                    finding_class=ResourceConsumptionFinding,
                    request=mutated_request,
                    parameter=parameter.display_name,
                    info="Timeout (" + parameter.display_name + ")",
                )

                log_orange("---")
                log_orange(Messages.MSG_TIMEOUT, page)
                log_orange(Messages.MSG_EVIL_REQUEST)
                log_orange(mutated_request.http_repr())
                log_orange("---")

                # Timeout can be a weak suspicion indicator
                suspicious = True
                continue
            except HTTPStatusError:
                self.network_errors += 1
                logging.error("Error: The server did not understand this request")
                continue
            except RequestError:
                self.network_errors += 1
                continue
            else:
                if self._check_crlf_injection(resp):
                    await self.add_low(
                        finding_class=CrlfFinding,
                        request=mutated_request,
                        parameter=parameter.display_name,
                        info=f"{self.MSG_VULN} via injection in the parameter {parameter.display_name}",
                        response=resp,
                    )

                    injection_msg = Messages.MSG_QS_INJECT if parameter.is_qs_injection else Messages.MSG_PARAM_INJECT

                    log_red("---")
                    log_red(injection_msg, self.MSG_VULN, page, parameter.display_name)
                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(mutated_request.http_repr())
                    log_red("---")

                    found = True
                    break
                else:
                    if self._is_suspicious(resp):
                        suspicious = True

        return found, suspicious

    # ---------------- Injection point: headers ----------------

    async def _test_header_injection(self, request: Request, quick: bool) -> Tuple[bool, bool]:
        """
        Inject CRLF payloads into HTTP headers.
        - Quick phase: fewer payloads + fewer headers
        - Full phase: full payloads + expanded headers
        Stops once a vulnerability is found for this endpoint.
        Returns: (found, suspicious)
        """
        import urllib.parse

        report_key = f"{request.method}:{request.path}"
        if report_key in self._reported_header_vuln:
            log_verbose(f"[!] Skipping header injection for {report_key} (already found)")
            return True, False

        headers_to_test = self.HEADER_QUICK if quick else self.HEADER_FULL

        found = False
        suspicious = False

        for payload_info in self._iter_payloads(quick, request, None):
            payload = (payload_info.payload or "").strip()
            if not payload:
                continue

            try:
                decoded_payload = urllib.parse.unquote(payload)
                decoded_payload.encode("ascii")
            except (UnicodeDecodeError, UnicodeEncodeError):
                continue

            for header_name in headers_to_test:
                base_headers = dict(request.headers) if request.headers is not None else {}
                injected_headers = {**base_headers, header_name: decoded_payload}

                log_verbose(f"[¨] Testing header {header_name}: {payload[:50]}")

                try:
                    resp = await self.crawler.async_send(request, headers=injected_headers)
                except (ReadTimeout, HTTPStatusError, RequestError, UnicodeEncodeError):
                    suspicious = True
                    continue

                if self._check_crlf_injection(resp):
                    vuln_request = Request(
                        request.url,
                        method=request.method,
                        get_params=request.get_params,
                        post_params=request.post_params,
                        file_params=request.file_params,
                        encoding=request.encoding,
                        referer=request.referer,
                        link_depth=request.link_depth,
                    )
                    vuln_request.set_headers(injected_headers)

                    await self.add_low(
                        finding_class=CrlfFinding,
                        request=vuln_request,
                        parameter=f"Header: {header_name}",
                        info=f"{self.MSG_VULN} via injection in HTTP header {header_name}",
                        response=resp,
                    )

                    log_red("---")
                    log_red(f"CRLF Injection in HTTP Header: {header_name}")
                    log_red(f"Payload: {payload}")
                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(vuln_request.http_repr())
                    log_red("---")

                    found = True
                    self._reported_header_vuln.add(report_key)
                    break

                if self._is_suspicious(resp):
                    suspicious = True

            if found:
                break

        return found, suspicious
