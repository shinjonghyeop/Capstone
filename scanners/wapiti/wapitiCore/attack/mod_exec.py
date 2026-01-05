#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2008-2025 Nicolas Surribas
# Copyright (C) 2021-2024 Cyberwatch
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
from os.path import join as path_join
from typing import Optional, Iterator

from httpx import ReadTimeout, RequestError

from wapitiCore.main.log import log_red, log_verbose, log_orange
from wapitiCore.attack.attack import Attack, Parameter
from wapitiCore.language.vulnerability import Messages
from wapitiCore.definitions.exec import CommandExecutionFinding
from wapitiCore.model import PayloadInfo
from wapitiCore.net.response import Response
from wapitiCore.definitions.resource_consumption import ResourceConsumptionFinding
from wapitiCore.definitions.internal_error import InternalErrorFinding
from wapitiCore.net import Request
from wapitiCore.parsers.ini_payload_parser import IniPayloadReader, replace_tags


class ModuleExec(Attack):
    """
    Detect scripts vulnerable to command and/or code execution.

    Also tests URL path-based command injection (e.g., /;id)
    """
    name = "exec"

    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        super().__init__(crawler, persister, attack_options, crawler_configuration)
        self.false_positive_timeouts = set()
        self.mutator = self.get_mutator()
        self.tested_paths = set()  # Track tested base URLs for path injection

    def get_payloads(self, _: Optional[Request] = None, __: Optional[Parameter] = None) -> Iterator[PayloadInfo]:
        """Load the payloads from the specified file"""
        parser = IniPayloadReader(path_join(self.DATA_DIR, "execPayloads.ini"))
        parser.add_key_handler("payload", replace_tags)
        parser.add_key_handler("rules", lambda x: x.splitlines() if x else [])

        yield from parser

    @staticmethod
    def _find_warning_in_response(data) -> str:
        warnings_and_infos = {
            "eval()'d code</b> on line <b>": "Warning eval()",
            "Cannot execute a blank command in": "Warning exec",
            "sh: command substitution:": "Warning exec",
            "Warning: usort()": "Warning usort()",
            "Warning: assert():": "Warning assert",
            "Failure evaluating code:": "Evaluation warning"
        }
        for warning, vuln_info in warnings_and_infos.items():
            if warning in data:
                return vuln_info
        return ""

    async def _test_path_injection(self, request: Request) -> bool:
        """Test command injection in URL path (e.g., /;id)"""
        from urllib.parse import urlparse

        parsed = urlparse(request.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Skip if already tested this base URL
        if base_url in self.tested_paths:
            return False
        self.tested_paths.add(base_url)

        # Key payloads for path-based command injection detection
        path_payloads = [
            # Linux command injection
            (";id", "uid=", "Command injection via semicolon in URL path"),
            ("|id", "uid=", "Command injection via pipe in URL path"),
            ("$(id)", "uid=", "Command injection via command substitution in URL path"),
            ("`id`", "uid=", "Command injection via backticks in URL path"),
            (";cat /etc/passwd", "root:", "Command injection reading /etc/passwd in URL path"),
            ("|cat /etc/passwd", "root:", "Command injection reading /etc/passwd in URL path"),
            # Windows command injection
            ("|dir", "Volume", "Windows command injection in URL path"),
            ("&dir", "Volume", "Windows command injection in URL path"),
            (";whoami", "\\", "Windows whoami injection in URL path"),
        ]

        for payload, expected, description in path_payloads:
            # Test payload in path: /payload
            test_url = f"{base_url}/{payload}"
            test_request = Request(test_url, method="GET")

            log_verbose(f"[¨] Testing path command injection: {test_url}")

            try:
                test_response = await self.crawler.async_send(test_request)
            except (ReadTimeout, RequestError):
                self.network_errors += 1
                continue

            if expected.lower() in test_response.content.lower():
                vuln_message = f"{description}: {test_url}"

                await self.add_critical(
                    finding_class=CommandExecutionFinding,
                    request=test_request,
                    info=vuln_message,
                    parameter="URL path",
                    response=test_response
                )

                log_red("---")
                log_red(f"[!] {description}")
                log_red(f"[!] URL: {test_url}")
                log_red("---")
                return True  # Found vulnerability, stop testing this URL

            # Also check for warning-based detection
            warning_info = self._find_warning_in_response(test_response.content)
            if warning_info:
                vuln_message = f"{warning_info} in URL path: {test_url}"

                await self.add_critical(
                    finding_class=CommandExecutionFinding,
                    request=test_request,
                    info=vuln_message,
                    parameter="URL path",
                    response=test_response
                )

                log_red("---")
                log_red(f"[!] {warning_info} in URL path")
                log_red(f"[!] URL: {test_url}")
                log_red("---")
                return True

        return False

    async def _test_parameter_fuzzing(self, request: Request) -> bool:
        """Test common hidden parameter names for command injection"""
        # Only fuzz POST requests
        if request.method != "POST":
            return False

        # Common parameter names used for command execution
        param_names = [
            "cmd", "command", "exec", "execute", "run", "shell",
            "cmd_input", "command_input", "exec_input", "input",
            "system", "syscmd", "do", "action", "code"
        ]

        # Simple payloads that work with strict filters (only lowercase letters)
        test_payloads = [
            ("id", ["uid=", "gid="]),
            ("whoami", ["root", "www-data", "apache", "nginx", "chall", "user"]),
            ("pwd", ["/var/www", "/home", "/app", "/usr", "/root"]),
        ]

        for param_name in param_names:
            for payload, expected_patterns in test_payloads:
                # Create a new request with the fuzzing parameter
                if request.post_params:
                    # Add to existing POST params
                    new_params = [(k, v) for k, v in request.post_params if k != param_name]
                    new_params.append((param_name, payload))
                else:
                    new_params = [(param_name, payload)]

                test_request = Request(
                    request.url,
                    method="POST",
                    post_params=new_params,
                    referer=request.referer
                )

                log_verbose(f"[¨] Testing hidden parameter {param_name}={payload}")

                try:
                    test_response = await self.crawler.async_send(test_request)
                except (ReadTimeout, RequestError):
                    self.network_errors += 1
                    continue

                # Check if any expected pattern is in response
                response_lower = test_response.content.lower()
                for expected in expected_patterns:
                    if expected.lower() in response_lower:
                        vuln_message = f"Command injection via hidden parameter {param_name}"

                        await self.add_critical(
                            finding_class=CommandExecutionFinding,
                            request=test_request,
                            info=vuln_message,
                            parameter=param_name,
                            response=test_response
                        )

                        log_red("---")
                        log_red(f"[!] Command injection found via parameter fuzzing")
                        log_red(f"[!] Hidden parameter: {param_name}")
                        log_red(f"[!] Payload: {payload}")
                        log_red(f"[!] URL: {request.url}")
                        log_red("---")
                        return True  # Found vulnerability

        return False

    async def attack(self, request: Request, response: Optional[Response] = None):
        warned = False
        timeouted = False
        page = request.path
        saw_internal_error = False
        current_parameter = None
        vulnerable_parameter = False

        # First, test URL path-based command injection
        await self._test_path_injection(request)

        # Second, try fuzzing common hidden parameter names for POST requests
        await self._test_parameter_fuzzing(request)

        for mutated_request, parameter, payload_info in self.mutator.mutate(request, self.get_payloads):

            if current_parameter != parameter:
                # Forget what we know about current parameter
                current_parameter = parameter
                vulnerable_parameter = False
            elif vulnerable_parameter:
                # If parameter is vulnerable, just skip till next parameter
                continue

            if payload_info.type == "time" and request.path_id in self.false_positive_timeouts:
                # If the original request is known to gives timeout and payload is time-based, just skip
                # and move to next payload
                continue

            log_verbose(f"[¨] {mutated_request}")

            try:
                response: Response = await self.crawler.async_send(mutated_request)
            except ReadTimeout:
                # Is the webpage expected to timeout?
                if payload_info.type == "time":
                    # Check for false-positive by asking the original request
                    if await self.does_timeout(request):
                        self.network_errors += 1
                        self.false_positive_timeouts.add(request.path_id)
                        continue

                    vuln_info = "Blind command execution"
                    if parameter.is_qs_injection:
                        vuln_message = Messages.MSG_QS_INJECT.format(vuln_info, page)
                    else:
                        vuln_message = f"{vuln_info} via injection in the parameter {parameter.display_name}"

                    await self.add_critical(
                        finding_class=CommandExecutionFinding,
                        request=mutated_request,
                        info=vuln_message,
                        parameter=parameter.display_name,
                    )

                    log_red("---")
                    log_red(
                        Messages.MSG_QS_INJECT if parameter.is_qs_injection else Messages.MSG_PARAM_INJECT,
                        vuln_info,
                        page,
                        parameter.display_name
                    )
                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(mutated_request.http_repr())
                    log_red("---")
                    vulnerable_parameter = True
                    continue

                # We didn't expect the webpage to timeout, this is an error
                self.network_errors += 1
                if timeouted:
                    continue

                # Log the request as a new timeout case
                log_orange("---")
                log_orange(Messages.MSG_TIMEOUT, page)
                log_orange(Messages.MSG_EVIL_REQUEST)
                log_orange(mutated_request.http_repr())
                log_orange("---")

                if parameter.is_qs_injection:
                    anom_msg = Messages.MSG_QS_TIMEOUT
                else:
                    anom_msg = Messages.MSG_PARAM_TIMEOUT.format(parameter.display_name)

                await self.add_medium(
                    finding_class=ResourceConsumptionFinding,
                    request=mutated_request,
                    info=anom_msg,
                    parameter=parameter.display_name,
                )
                timeouted = True
            except RequestError:
                self.network_errors += 1
            else:
                if payload_info.type == "time":
                    continue

                vuln_info = None

                # No timeout raised, check for patterns in response
                if any(rule.replace("[SPACE]", " ") in response.content for rule in payload_info.rules):
                    vuln_info = payload_info.description
                    # We reached maximum exploitation for this parameter, don't send more payloads
                    vulnerable_parameter = True
                elif not warned:
                    vuln_info = self._find_warning_in_response(response.content)
                    warned = True

                if vuln_info:
                    # An error message implies that a vulnerability may exist

                    if parameter.is_qs_injection:
                        vuln_message = Messages.MSG_QS_INJECT.format(vuln_info, page)
                        log_message = Messages.MSG_QS_INJECT
                    else:
                        vuln_message = f"{vuln_info} via injection in the parameter {parameter.display_name}"
                        log_message = Messages.MSG_PARAM_INJECT

                    await self.add_critical(
                        finding_class=CommandExecutionFinding,
                        request=mutated_request,
                        info=vuln_message,
                        parameter=parameter.display_name,
                        response=response
                    )

                    log_red("---")
                    log_red(
                        log_message,
                        vuln_info,
                        page,
                        parameter.display_name
                    )
                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(mutated_request.http_repr())
                    log_red("---")
                elif response.is_server_error and not saw_internal_error:
                    saw_internal_error = True
                    if parameter.is_qs_injection:
                        anom_msg = Messages.MSG_QS_500
                    else:
                        anom_msg = Messages.MSG_PARAM_500.format(parameter.display_name)

                    await self.add_high(
                        finding_class=InternalErrorFinding,
                        request=mutated_request,
                        info=anom_msg,
                        parameter=parameter.display_name,
                    )

                    log_orange("---")
                    log_orange(Messages.MSG_500, page)
                    log_orange(Messages.MSG_EVIL_REQUEST)
                    log_orange(mutated_request.http_repr())
                    log_orange("---")
