#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2021-2025 Nicolas Surribas
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
from typing import List

from wapitiCore.definitions.base import FindingBase


class SSTIFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Server-Side Template Injection"

    @classmethod
    def description(cls) -> str:
        return (
            "Server-Side Template Injection (SSTI) occurs when an attacker can inject "
            "malicious input into a server-side template, causing the template engine "
            "to execute arbitrary code on the server."
        ) + " " + (
            "This vulnerability arises when user input is embedded within templates "
            "rendered by templating engines like Jinja2, Twig, Freemarker, or Velocity "
            "without proper sanitization or validation."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Server-Side Template Injection",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/"
                    "07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection"
                )
            },
            {
                "title": "PortSwigger: Server-Side Template Injection",
                "url": "https://portswigger.net/web-security/server-side-template-injection"
            },
            {
                "title": "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine",
                "url": "https://cwe.mitre.org/data/definitions/1336.html"
            },
            {
                "title": "PayloadsAllTheThings: Server Side Template Injection",
                "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection"
            },
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Never allow user input to be directly concatenated into templates. "
            "Use the template engine's built-in mechanisms for passing variables safely. "
            "Implement strict input validation and consider using a sandboxed template environment. "
            "Keep template engines updated to patch known vulnerabilities."
        )

    @classmethod
    def short_name(cls) -> str:
        return "SSTI"

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-INPV-18"]
