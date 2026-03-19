#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHP反序列化漏洞模式检测器
用于检测无类场景下的反序列化漏洞
"""

import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum


class VulnerabilityType(Enum):
    FILTER_BYPASS = "filter_bypass"
    ARRAY_INJECTION = "array_injection"
    PHAR_DESERIALIZATION = "phar_deserialization"
    SESSION_UNSERIALIZE = "session_unserialize"
    OBJECT_INJECTION = "object_injection"
    STRING_ESCAPE = "string_escape"
    VARIABLE_OVERRIDE = "variable_override"
    UNKNOWN = "unknown"


@dataclass
class FilterRule:
    name: str
    pattern: str
    replace_with: str
    bypass_method: str
    bypass_example: str


@dataclass
class VulnerabilityPattern:
    vuln_type: VulnerabilityType
    confidence: float
    description: str
    location: str
    details: Dict[str, Any] = field(default_factory=dict)
    payloads: List[str] = field(default_factory=list)


class PatternDetector:
    FILTER_PATTERNS = {
        'php': {'bypass': 'pphphp', 'bypass2': 'phpphp'},
        'flag': {'bypass': 'fl3g', 'bypass2': 'flflagag'},
        'php5': {'bypass': 'phphp5p'},
        'php4': {'bypass': 'phphp4p'},
        'fl1g': {'bypass': 'fl1fl1g'},
    }

    def __init__(self, code: str):
        self.code = code
        self.patterns: List[VulnerabilityPattern] = []

    def detect_all(self) -> List[VulnerabilityPattern]:
        self.patterns = []

        self._detect_filter_bypass()
        self._detect_array_injection()
        self._detect_phar_deserialization()
        self._detect_session_unserialize()
        self._detect_object_injection()
        self._detect_string_escape()
        self._detect_variable_override()

        return self.patterns

    def _detect_filter_bypass(self):
        filter_func_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}'
        has_serialize = 'serialize' in self.code
        has_unserialize = 'unserialize' in self.code

        for match in re.finditer(filter_func_pattern, self.code, re.DOTALL):
            func_name = match.group(1)
            func_body = match.group(2)

            if 'preg_replace' not in func_body:
                continue

            filter_arr_match = re.search(r'\$filter_arr\s*=\s*array\(([^)]+)\)', func_body)
            if filter_arr_match:
                filters = [f.strip().strip("'\"") for f in filter_arr_match.group(1).split(',')]

                preg_replace_match = re.search(
                    r"preg_replace\s*\(\s*['\"]/\^?([^'\"]+)['\"]\s*/i?s?\s*,\s*['\"]([^'\"]*)['\"]",
                    func_body
                )
                replace_with = preg_replace_match.group(2) if preg_replace_match else ''

                if replace_with == '' or replace_with == '空':
                    replace_with = ''

                if has_serialize and has_unserialize:
                    location = f"function {func_name}()"
                    details = {
                        'function': func_name,
                        'filters': filters,
                        'replace_with': replace_with,
                        'bypass_methods': self._generate_bypass_methods(filters)
                    }

                    payloads = self._generate_filter_bypass_payloads(filters)

                    vuln = VulnerabilityPattern(
                        vuln_type=VulnerabilityType.FILTER_BYPASS,
                        confidence=0.95,
                        description=f"检测到preg_replace过滤器绕过漏洞，过滤关键词: {', '.join(filters)}",
                        location=location,
                        details=details,
                        payloads=payloads
                    )
                    self.patterns.append(vuln)

    def _generate_bypass_methods(self, filters: List[str]) -> Dict[str, str]:
        methods = {}
        for f in filters:
            if f.lower() in self.FILTER_PATTERNS:
                methods[f] = self.FILTER_PATTERNS[f.lower()]['bypass']
            else:
                for known, patterns in self.FILTER_PATTERNS.items():
                    if known in f.lower():
                        methods[f] = patterns['bypass']
                        break
                else:
                    doubled = f + f
                    methods[f] = doubled
        return methods

    def _generate_filter_bypass_payloads(self, filters: List[str]) -> List[str]:
        payloads = []

        base_serial = 'a:3:{s:4:"user";s:5:"guest";s:8:"function";s:10:"show_image";s:3:"img";s:18:"Z3Vlc3RfaW1nLnBuZw==";}'

        replacements = {
            'flag': ['fl3g', 'fl4g', 'fla', 'f1ag', 'f1g', 'FLAG', 'FlAg', 'fl\\x67'],
            'fl1g': ['fl3g', 'fl4g', 'f1ag', 'flAg', 'fl1fl1g'],
            'php': ['pphphp', 'phphp', 'php5', 'PHP', 'PhP'],
            'php5': ['php', 'pphphp5'],
            'php4': ['php', 'pphphp4'],
        }

        for f in filters:
            if f.lower() in replacements:
                for repl in replacements[f.lower()]:
                    test_serial = base_serial.replace('Z3Vlc3RfaW1nLnBuZw==', repl)
                    test_serial = test_serial.replace('s:18:"Z3Vlc3RfaW1nLnBuZw=="', f's:{len(repl)}:"{repl}"')
                    if test_serial != base_serial:
                        payloads.append(test_serial)

        escaped = base_serial.replace('"', '\\"')
        payloads.append(escaped)

        return list(set(payloads))[:10]

    def _detect_array_injection(self):
        if 'serialize($_' in self.code or 'unserialize($_' in self.code:
            array_match = re.search(r'(serialize|unserialize)\s*\(\s*\$_(\w+)\s*\)', self.code)
            if array_match:
                vuln = VulnerabilityPattern(
                    vuln_type=VulnerabilityType.ARRAY_INJECTION,
                    confidence=0.85,
                    description=f"检测到数组序列化/反序列化操作: {array_match.group(0)}",
                    location=f"line ~{self.code[:array_match.start()].count(chr(10)) + 1}",
                    details={
                        'function': array_match.group(1),
                        'source': f"$_{array_match.group(2)}"
                    }
                )
                self.patterns.append(vuln)

    def _detect_phar_deserialization(self):
        phar_patterns = [
            r'phar://',
            r'compress\.zlib://phar',
            r'compress\.bzip2://phar',
            r'zip://[^#\s]+#',
        ]

        for pattern in phar_patterns:
            matches = list(re.finditer(pattern, self.code))
            if matches:
                vuln = VulnerabilityPattern(
                    vuln_type=VulnerabilityType.PHAR_DESERIALIZATION,
                    confidence=0.9,
                    description=f"检测到Phar反序列化相关协议: {pattern}",
                    location=f"发现 {len(matches)} 处",
                    details={'protocol': pattern, 'count': len(matches)}
                )
                self.patterns.append(vuln)
                break

        if 'unserialize(' in self.code:
            unserialize_lines = [i for i, line in enumerate(self.code.split('\n')) if 'unserialize(' in line]
            for line_num in unserialize_lines:
                context = '\n'.join(self.code.split('\n')[max(0, line_num-2):line_num+3])
                if any(proto in context for proto in ['phar://', 'http://', 'ftp://', 'zip://']):
                    vuln = VulnerabilityPattern(
                        vuln_type=VulnerabilityType.OBJECT_INJECTION,
                        confidence=0.75,
                        description="检测到unserialize结合文件操作的利用可能性",
                        location=f"line {line_num + 1}",
                        details={'line': line_num + 1}
                    )
                    self.patterns.append(vuln)

    def _detect_session_unserialize(self):
        session_patterns = [
            r'session_start\s*\(',
            r'SessionHandler',
            r'session_decode\s*\(',
            r'\$_SESSION\s*=',
            r'session_register\s*\(',
        ]

        for pattern in session_patterns:
            matches = list(re.finditer(pattern, self.code))
            if matches:
                has_unserialize = 'unserialize(' in self.code
                vuln = VulnerabilityPattern(
                    vuln_type=VulnerabilityType.SESSION_UNSERIALIZE,
                    confidence=0.8 if has_unserialize else 0.5,
                    description=f"检测到Session处理相关代码: {pattern}",
                    location=f"发现 {len(matches)} 处",
                    details={
                        'pattern': pattern,
                        'has_unserialize': has_unserialize
                    }
                )
                self.patterns.append(vuln)
                break

    def _detect_object_injection(self):
        unserialize_pattern = r'unserialize\s*\(\s*([^)]+)\)'
        for match in re.finditer(unserialize_pattern, self.code):
            source = match.group(1).strip()
            if '$_' in source or '$' in source:
                vuln = VulnerabilityPattern(
                    vuln_type=VulnerabilityType.OBJECT_INJECTION,
                    confidence=0.7,
                    description="检测到用户输入的反序列化入口点",
                    location=f"unserialize({source})",
                    details={'source': source}
                )
                self.patterns.append(vuln)

    def _detect_string_escape(self):
        patterns = [
            (r'\\\\"', '双引号逃逸'),
            (r'\\x', '十六进制逃逸'),
            (r'\.\s*"\s*"', '字符串拼接逃逸'),
        ]

        for pattern, desc in patterns:
            if re.search(pattern, self.code):
                vuln = VulnerabilityPattern(
                    vuln_type=VulnerabilityType.STRING_ESCAPE,
                    confidence=0.6,
                    description=f"检测到字符串逃逸模式: {desc}",
                    location="code",
                    details={'pattern': pattern}
                )
                self.patterns.append(vuln)

    def _detect_variable_override(self):
        dangerous_funcs = [
            ('extract($_', VulnerabilityType.VARIABLE_OVERRIDE, 'extract()变量覆盖'),
            ('parse_str($_', VulnerabilityType.VARIABLE_OVERRIDE, 'parse_str()变量覆盖'),
            ('parse_str($', VulnerabilityType.VARIABLE_OVERRIDE, 'parse_str()变量覆盖'),
            ('import_request_variables(', VulnerabilityType.VARIABLE_OVERRIDE, 'import_request_variables()'),
        ]

        for pattern, vuln_type, desc in dangerous_funcs:
            if pattern in self.code:
                matches = list(re.finditer(re.escape(pattern), self.code))
                if matches:
                    vuln = VulnerabilityPattern(
                        vuln_type=vuln_type,
                        confidence=0.75,
                        description=f"检测到{dangerous_funcs}",
                        location=f"发现 {len(matches)} 处",
                        details={'function': desc, 'count': len(matches)}
                    )
                    self.patterns.append(vuln)
                    break

    def get_report(self) -> str:
        if not self.patterns:
            return "未检测到明显的漏洞模式"

        report = []
        report.append("\n" + "="*70)
        report.append("  漏洞模式检测结果")
        report.append("="*70)

        for i, pattern in enumerate(self.patterns, 1):
            report.append(f"\n[{i}] {pattern.vuln_type.value.upper()}")
            report.append(f"    置信度: {pattern.confidence:.0%}")
            report.append(f"    描述: {pattern.description}")
            report.append(f"    位置: {pattern.location}")

            if pattern.details:
                report.append(f"    详情:")
                for key, value in pattern.details.items():
                    report.append(f"      - {key}: {value}")

            if pattern.payloads:
                report.append(f"    推荐Payload (前3个):")
                for payload in pattern.payloads[:3]:
                    if len(payload) > 60:
                        report.append(f"      {payload[:60]}...")
                    else:
                        report.append(f"      {payload}")

        return '\n'.join(report)


class FilterBypassGenerator:
    def __init__(self, filters: List[str], replace_with: str = ''):
        self.filters = filters
        self.replace_with = replace_with

    def generate_all_bypasses(self) -> Dict[str, List[str]]:
        result = {}
        for f in self.filters:
            result[f] = self._generate_bypasses_for_filter(f)
        return result

    def _generate_bypasses_for_filter(self, filter_str: str) -> List[str]:
        bypasses = []

        doubled = filter_str + filter_str
        bypasses.append(doubled)

        if len(filter_str) >= 3:
            mid = len(filter_str) // 2
            part1 = filter_str[:mid]
            part2 = filter_str[mid:]
            bypasses.append(part1 + filter_str + part2)

        if filter_str.lower() == 'flag':
            bypasses.extend(['fl3g', 'fla', 'fl\x67', 'fLAG'])
        elif filter_str.lower() == 'php':
            bypasses.extend(['pphphp', 'phphp', 'phpphp'])
        elif filter_str.lower() == 'fl1g':
            bypasses.extend(['fl1g', 'f1ag', 'f1g'])

        char_variations = []
        for i, char in enumerate(filter_str):
            if char.isdigit():
                char_variations.append(filter_str[:i] + chr(ord(char) + (1 if char == '1' else -1)) + filter_str[i+1:])
        bypasses.extend(char_variations)

        return list(set(bypasses))[:10]

    def generate_payloads(self, serialized_template: str) -> List[Dict[str, str]]:
        payloads = []
        all_bypasses = self.generate_all_bypasses()

        for filter_str, bypass_list in all_bypasses.items():
            for bypass in bypass_list:
                new_payload = serialized_template.replace(filter_str, bypass)
                if new_payload != serialized_template:
                    payloads.append({
                        'filter': filter_str,
                        'bypass': bypass,
                        'payload': new_payload,
                        'type': 'double_write'
                    })

        for filter_str in self.filters:
            if filter_str.lower() == 'flag':
                new_payload = serialized_template.replace('flag', 'fl3g')
                if new_payload != serialized_template:
                    payloads.append({
                        'filter': filter_str,
                        'bypass': 'fl3g',
                        'payload': new_payload,
                        'type': 'char_replace'
                    })

        return payloads
