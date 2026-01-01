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
from wapitiCore.definitions.ssti import SSTIFinding
from wapitiCore.model import PayloadInfo
from wapitiCore.net.response import Response
from wapitiCore.definitions.resource_consumption import ResourceConsumptionFinding
from wapitiCore.definitions.internal_error import InternalErrorFinding
from wapitiCore.net import Request
from wapitiCore.parsers.ini_payload_parser import IniPayloadReader, replace_tags


class ModuleSsti(Attack):
    """
    Detect Server-Side Template Injection (SSTI) vulnerabilities.

    This module tests for SSTI vulnerabilities across various template engines:
    - Python: Jinja2, Mako, Django, Tornado
    - Java: Freemarker, Velocity, Pebble, Thymeleaf, SpEL
    - PHP: Twig, Smarty, Blade, Latte
    - JavaScript: Handlebars, EJS, Pug, Lodash, Nunjucks
    """
    name = "ssti"

    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        super().__init__(crawler, persister, attack_options, crawler_configuration)
        self.mutator = self.get_mutator()

    def get_payloads(self, _: Optional[Request] = None, __: Optional[Parameter] = None) -> Iterator[PayloadInfo]:
        """Load the SSTI payloads from the specified file"""
        parser = IniPayloadReader(path_join(self.DATA_DIR, "sstiPayloads.ini"))
        parser.add_key_handler("payload", replace_tags)
        parser.add_key_handler("rules", lambda x: x.splitlines() if x else [])

        yield from parser

    @staticmethod
    def _find_ssti_error_in_response(data: str) -> str:
        """Check for template engine error messages that indicate SSTI vulnerability"""
        error_patterns = {
            # Jinja2/Python errors
            "jinja2.exceptions": "Jinja2 template error",
            "TemplateSyntaxError": "Template syntax error",
            "UndefinedError": "Template undefined error",
            "TemplateNotFound": "Template not found error",
            # Twig/PHP errors
            "Twig_Error": "Twig template error",
            "Twig\\Error": "Twig template error",
            # Freemarker/Java errors
            "freemarker.template": "Freemarker template error",
            "FreeMarker template error": "Freemarker template error",
            "freemarker.core": "Freemarker core error",
            # Velocity errors
            "org.apache.velocity": "Velocity template error",
            "VelocityException": "Velocity template error",
            # Smarty errors
            "Smarty error": "Smarty template error",
            "SmartyCompilerException": "Smarty template error",
            # Thymeleaf errors
            "org.thymeleaf": "Thymeleaf template error",
            "TemplateProcessingException": "Thymeleaf template error",
            # Pebble errors
            "com.mitchellbosecke.pebble": "Pebble template error",
            "PebbleException": "Pebble template error",
            # Mako errors
            "mako.exceptions": "Mako template error",
            "MakoException": "Mako template error",
            # Django errors
            "django.template": "Django template error",
            "TemplateSyntaxError": "Django template error",
            # SpEL errors
            "SpelEvaluationException": "SpEL evaluation error",
            "SpelParseException": "SpEL parse error",
            "ELException": "Expression Language error",
            # Handlebars errors
            "Handlebars.Exception": "Handlebars template error",
            # EJS errors
            "EJS Error": "EJS template error",
            # General errors
            "TemplateError": "Template error detected",
            "template error": "Template error detected",
            "ParseException": "Template parse exception",
        }
        for pattern, vuln_info in error_patterns.items():
            if pattern in data:
                return vuln_info
        return ""

    async def attack(self, request: Request, response: Optional[Response] = None):
        page = request.path
        saw_internal_error = False
        current_parameter = None
        vulnerable_parameter = False

        for mutated_request, parameter, payload_info in self.mutator.mutate(request, self.get_payloads):

            if current_parameter != parameter:
                # Forget what we know about current parameter
                current_parameter = parameter
                vulnerable_parameter = False
            elif vulnerable_parameter:
                # If parameter is vulnerable, just skip till next parameter
                continue

            log_verbose(f"[¨] {mutated_request}")

            try:
                response: Response = await self.crawler.async_send(mutated_request)
            except ReadTimeout:
                self.network_errors += 1
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
                continue
            except RequestError:
                self.network_errors += 1
                continue

            vuln_info = None

            # Check for patterns in response that indicate successful SSTI
            if payload_info.rules and any(
                rule.strip() in response.content for rule in payload_info.rules if rule.strip()
            ):
                # Get first line of messages as description
                messages = payload_info.messages if payload_info.messages else ""
                vuln_info = messages.split('\n')[0].strip() if messages else "Server-Side Template Injection"
                # We reached maximum exploitation for this parameter, don't send more payloads
                vulnerable_parameter = True
            else:
                # Check for error-based SSTI detection
                error_info = self._find_ssti_error_in_response(response.content)
                if error_info:
                    vuln_info = error_info

            if vuln_info:
                # SSTI vulnerability detected
                if parameter.is_qs_injection:
                    vuln_message = Messages.MSG_QS_INJECT.format(vuln_info, page)
                    log_message = Messages.MSG_QS_INJECT
                else:
                    vuln_message = f"{vuln_info} via injection in the parameter {parameter.display_name}"
                    log_message = Messages.MSG_PARAM_INJECT

                await self.add_critical(
                    finding_class=SSTIFinding,
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
