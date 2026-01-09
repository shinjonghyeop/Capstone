#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from os.path import join as path_join
from typing import Optional, Iterator

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

    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        super().__init__(crawler, persister, attack_options, crawler_configuration)
        self.mutator = self.get_mutator()
        self._reported_header_vuln = set()

    def get_payloads(self, _: Optional[Request] = None, __: Optional[Parameter] = None) -> Iterator[PayloadInfo]:
        """Load the payloads from the specified file."""
        payload_reader = TxtPayloadReader(path_join(self.DATA_DIR, self.PAYLOADS_FILE))
        yield from payload_reader

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
        # try:
        #     # response.content가 이미 str인 경우 처리
        #     if isinstance(response.content, bytes):
        #         body = response.content.decode('utf-8', errors='ignore')
        #     else:
        #         body = str(response.content)
        
        #     body_lower = body.lower()
        
        #     if 'flag' in body_lower:
        #         return True
        # except Exception as e:
        #     import traceback
        #     traceback.print_exc()
        
        return False

    async def attack(self, request: Request, response: Optional[Response] = None):
        page = request.path

        # 1) Parameter mutation (crlfPayloads.txt is used)
        for mutated_request, parameter, _payload in self.mutator.mutate(
            request,
            self.get_payloads,
        ):
            log_verbose(f"[¨] {mutated_request.url}")

            try:
                response = await self.crawler.async_send(mutated_request)
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
            except HTTPStatusError:
                self.network_errors += 1
                logging.error("Error: The server did not understand this request")
            except RequestError:
                self.network_errors += 1
            else:
                if self._check_crlf_injection(response):
                    await self.add_low(
                        finding_class=CrlfFinding,
                        request=mutated_request,
                        parameter=parameter.display_name,
                        info=f"{self.MSG_VULN} via injection in the parameter {parameter.display_name}",
                        response=response,
                    )

                    injection_msg = Messages.MSG_QS_INJECT if parameter.is_qs_injection else Messages.MSG_PARAM_INJECT

                    log_red("---")
                    log_red(injection_msg, self.MSG_VULN, page, parameter.display_name)
                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(mutated_request.http_repr())
                    log_red("---")

        # 2) Header injection tests (reuses crlfPayloads.txt)
        await self._test_header_injection(request)

        # 3) Path injection tests (contains hard-coded payloads)
        await self._test_path_injection(request)

    async def _test_header_injection(self, request: Request):
        """
        Inject CRLF payloads into HTTP headers (reuses crlfPayloads.txt).
        Stops testing remaining headers once a vulnerability is found for this endpoint.
        """
        import urllib.parse

        # 엔드포인트별 취약점 발견 여부 추적
        report_key = f"{request.method}:{request.path}"
        
        # 이미 이 엔드포인트에서 헤더 취약점을 발견했다면 스킵
        if report_key in self._reported_header_vuln:
            log_verbose(f"[!] Skipping header injection for {report_key} (already found)")
            return

        test_headers = [
            "X-Forwarded-For",
            "X-Forwarded-Host",
            "User-Agent",
            "Referer",
            "X-Original-URL",
            "X-Custom-Header",
        ]

        # 취약점 발견 시 True로 설정되어 루프 종료
        vulnerability_found = False

        for payload_info in self.get_payloads(request, None):
            if vulnerability_found:
                break

            payload = payload_info.payload

            try:
                decoded_payload = urllib.parse.unquote(payload)
                decoded_payload.encode("ascii")
            except (UnicodeDecodeError, UnicodeEncodeError):
                continue

            # 각 헤더 테스트
            for header_name in test_headers:
                if vulnerability_found:
                    break

                base_headers = dict(request.headers) if request.headers is not None else {}
                injected_headers = {**base_headers, header_name: decoded_payload}

                log_verbose(f"[¨] Testing header {header_name}: {payload[:50]}")

                try:
                    response = await self.crawler.async_send(request, headers=injected_headers)
                except (ReadTimeout, HTTPStatusError, RequestError, UnicodeEncodeError):
                    continue

                if self._check_crlf_injection(response):
                    # 취약점 발견!
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
                        response=response,
                    )

                    log_red("---")
                    log_red(f"CRLF Injection in HTTP Header: {header_name}")
                    log_red(f"Payload: {payload}")
                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(vuln_request.http_repr())
                    log_red("---")

                    # 이 엔드포인트에서 취약점을 찾았으므로 종료
                    vulnerability_found = True
                    self._reported_header_vuln.add(report_key)
                    
                    log_verbose(f"[+] Found CRLF in header {header_name}, skipping remaining headers for {report_key}")
                    break  # 헤더 루프 탈출

            # 취약점을 찾았으면 페이로드 루프도 탈출
            if vulnerability_found:
                break

    async def _test_path_injection(self, request: Request):
        """
        Inject CRLF payloads into URL path for ALL paths.
        Reuses payloads from crlfPayloads.txt (no hard-coded list).
        """
        import re
        from urllib.parse import quote

        # IMPORTANT: use request.path (no query string) as base
        base_path_url = request.path.rstrip("/")

        # CRLF 관련 페이로드만 선별하기 위한 간단 필터(필요시 확장)
        # - %0d, %0a, %u000d, %u000a, double-encoded 등
        crlf_pattern = re.compile(r"(%0d|%0a|%u0*0d|%u0*0a|%250d|%250a)", re.IGNORECASE)

        selected_payloads = []
        seen = set()

        for payload_info in self.get_payloads(request, None):
            raw = (payload_info.payload or "").strip()
            if not raw:
                continue

            # Path 테스트에서는 "실제로 개행을 유발할 가능성이 있는" 것 위주로 제한
            if not crlf_pattern.search(raw) and ("\r" not in raw and "\n" not in raw):
                continue

            # 중복 제거
            key = raw.lower()
            if key in seen:
                continue
            seen.add(key)

            # Path segment로 안전하게 쓰기:
            # - 기존 % 시퀀스는 유지(%는 safe)
            # - 공백/특수문자 등은 인코딩
            #   (payload가 이미 URL-encoded 형태라도, 안전하게 segment 처리하는 목적)
            safe_payload = raw.replace("\r", "%0d").replace("\n", "%0a")
            safe_payload = quote(safe_payload, safe="%")  # preserve existing %xx

            selected_payloads.append(safe_payload)

        # 실제 테스트 수행: 모든 경로에 대해 path segment append 방식
        for payload in selected_payloads:
            test_url = f"{base_path_url}/{payload}"

            log_verbose(f"[¨] Testing path: {test_url[:120]}...")

            try:
                test_request = Request(
                    test_url,
                    method=request.method,
                    get_params=request.get_params,     # 기존 query 유지(원하면 제거 가능)
                    post_params=request.post_params,
                    file_params=request.file_params,
                    encoding=request.encoding,
                    referer=request.referer,
                    link_depth=request.link_depth
                )
                response = await self.crawler.async_send(test_request)
            except (ReadTimeout, HTTPStatusError, RequestError, UnicodeEncodeError):
                continue

            if self._check_crlf_injection(response):
                await self.add_low(
                    finding_class=CrlfFinding,
                    request=test_request,
                    parameter="URL Path",
                    info=f"{self.MSG_VULN} via injection in URL path",
                    response=response,
                )

                log_red("---")
                log_red("CRLF Injection in URL Path")
                log_red(f"Full URL: {test_url}")
                log_red(Messages.MSG_EVIL_REQUEST)
                log_red(test_request.http_repr())
                log_red("---")
