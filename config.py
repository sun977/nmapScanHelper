#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
扫描配置文件
"""

# 扫描配置
SCAN_CONFIG = {
    # 基本配置
    'networks_file': 'networks.txt',
    'output_file': 'result_dns.csv',
    
    # 扫描模式配置
    'enable_host_discovery': True,  # 是否启用主机发现 (-sn)
    'enable_tcp_scan': True,        # 是否启用TCP扫描
    'enable_udp_scan': True,        # 是否启用UDP扫描
    
    # 扫描参数
    'scan_modes': {
        'normal': {
            'tcp_args': '-sS --open',           # 默认TCP SYN扫描
            'udp_args': '-sU --open',           # 默认UDP扫描
            'timing': '',                       # 默认时序
        },
        'stealth': {
            'tcp_args': '-sS --open -T2',       # 隐蔽TCP扫描
            'udp_args': '-sU --open -T2',       # 隐蔽UDP扫描
            'timing': '-T2',                    # 慢速扫描
        },
        'aggressive': {
            'tcp_args': '-sT --open -T4',       # TCP Connect扫描
            'udp_args': '-sU --open -T4',       # 快速UDP扫描
            'timing': '-T4',                    # 快速扫描
        },
        'comprehensive': {
            'tcp_args': '-sS -sT --open -T3',   # 综合TCP扫描
            'udp_args': '-sU --open -T3',       # 标准UDP扫描
            'timing': '-T3',                    # 标准时序
        }
    },
    
    # 默认扫描模式
    'default_scan_mode': 'normal',
    
    # 超时设置
    'host_timeout': '30s',              # 主机超时
    'scan_timeout': '300s',             # 扫描超时
    
    # 其他参数
    'max_retries': 2,                   # 最大重试次数
    'parallel_processes': 1,            # 并行进程数
    'verbose': True,                    # 详细输出
}

# 特殊环境配置
SPECIAL_ENV_CONFIG = {
    'firewall_bypass': {
        'description': '防火墙绕过模式',
        'tcp_args': '-sT -Pn --open -T2',
        'udp_args': '-sU -Pn --open -T1',
        'host_discovery': '-Pn',
    },
    'fast_scan': {
        'description': '快速扫描模式',
        'tcp_args': '-sS --open -T5 --min-rate=1000',
        'udp_args': '-sU --open -T5 --min-rate=500',
        'host_discovery': '-sn -T5',
    },
    'quiet_scan': {
        'description': '静默扫描模式',
        'tcp_args': '-sS --open -T1 -f',
        'udp_args': '-sU --open -T1',
        'host_discovery': '-sn -T1',
    }
}