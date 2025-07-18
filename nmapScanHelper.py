#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Version: 1.0.0
Author: Sun977
Update: 2025-07-18
Description: 增强版本 - 支持任意端口扫描和多种扫描模式
Nmap 端口扫描辅助脚本
"""

import nmap
import csv
import sys
import os
import argparse
from datetime import datetime
from config import SCAN_CONFIG, SPECIAL_ENV_CONFIG  # 直接引入配置文件

def read_networks(filename):
    """
    从文件中读取网段信息
    """
    networks = []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    networks.append(line)
    except FileNotFoundError:
        print(f"错误: 找不到文件 {filename}")
        sys.exit(1)
    except Exception as e:
        print(f"读取文件时出错: {e}")
        sys.exit(1)
    
    return networks

def run_nmap_scan(network, port, port_type, scan_mode='normal', special_env=None):
    """
    执行nmap扫描
    scan_mode: 'normal', 'stealth', 'aggressive', 'comprehensive'
    special_env: 特殊环境配置
    """
    nm = nmap.PortScanner()
    
    try:
        mode_desc = special_env if special_env else scan_mode
        print(f"正在扫描 {network} 的 {port_type.upper()}/{port} 端口 ({mode_desc}模式)...")
        
        # 获取扫描参数
        if special_env and special_env in SPECIAL_ENV_CONFIG:
            if port_type == 'tcp':
                scan_args = SPECIAL_ENV_CONFIG[special_env]['tcp_args']
            else:
                scan_args = SPECIAL_ENV_CONFIG[special_env]['udp_args']
        else:
            config = SCAN_CONFIG['scan_modes'].get(scan_mode, SCAN_CONFIG['scan_modes']['normal'])
            if port_type == 'tcp':
                scan_args = config['tcp_args']
            else:
                scan_args = config['udp_args']
        
        # 执行扫描
        result = nm.scan(network, str(port), scan_args)
        return nm
        
    except nmap.PortScannerError as e:
        print(f"Nmap扫描错误: {e}")
        return None
    except Exception as e:
        print(f"扫描时出错: {e}")
        return None

def parse_nmap_results(nm, port, protocol):
    """
    解析nmap扫描结果
    """
    results = []
    
    try:
        for host in nm.all_hosts():
            # 检查主机状态
            if nm[host].state() != 'up':
                continue
            
            # 检查指定端口是否开放
            if protocol in nm[host] and port in nm[host][protocol]:
                port_info = nm[host][protocol][port]
                if port_info['state'] == 'open':
                    service_name = port_info.get('name', 'unknown')
                    
                    results.append({
                        'ip': host,
                        'port': str(port),
                        'protocol': protocol,
                        'state': 'open',
                        'service': service_name
                    })
    except Exception as e:
        print(f"处理扫描结果时出错: {e}")
    
    return results

def save_to_csv(results, filename):
    """
    将结果保存到CSV文件
    """
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['scan_time', 'network', 'ip', 'port', 'protocol', 'state', 'service']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in results:
                writer.writerow(result)
        
        print(f"结果已保存到 {filename}")
    except Exception as e:
        print(f"保存CSV文件时出错: {e}")

def run_host_discovery(network, special_env=None):
    """
    执行主机发现扫描 (-sn)
    """
    nm = nmap.PortScanner()
    
    try:
        print(f"正在进行主机发现扫描: {network}...")
        
        # 获取主机发现参数
        if special_env and special_env in SPECIAL_ENV_CONFIG:
            discovery_args = SPECIAL_ENV_CONFIG[special_env]['host_discovery']
        else:
            discovery_args = '-sn'
        
        result = nm.scan(network, arguments=discovery_args)
        
        alive_hosts = []
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                alive_hosts.append(host)
        
        print(f"发现 {len(alive_hosts)} 个活跃主机")
        return alive_hosts
    except Exception as e:
        print(f"主机发现扫描出错: {e}")
        return []

def parse_arguments():
    """
    解析命令行参数
    """
    parser = argparse.ArgumentParser(
        description='Nmap 端口扫描工具 (增强版)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
扫描模式说明:
  normal      - 标准扫描模式 (默认)
  stealth     - 隐蔽扫描模式 (慢速，不易被发现)
  aggressive  - 快速扫描模式 (使用TCP Connect)
  comprehensive - 综合扫描模式 (多种技术结合)

特殊环境模式:
  firewall_bypass - 防火墙绕过模式
  fast_scan      - 快速扫描模式
  quiet_scan     - 静默扫描模式

示例:
  python3 nmap_dns_scanner.py --port 53
  python3 nmap_dns_scanner.py --port 80 --mode stealth
  python3 nmap_dns_scanner.py --port 22 --special-env firewall_bypass
  python3 nmap_dns_scanner.py --port 443 --tcp-only
        """
    )
    
    parser.add_argument('-p', '--port',
                       type=int,
                       default=53,
                       help='要扫描的端口号 (默认: 53)')
    
    parser.add_argument('-m', '--mode', 
                       choices=['normal', 'stealth', 'aggressive', 'comprehensive'],
                       default=SCAN_CONFIG['default_scan_mode'],
                       help='扫描模式 (默认: normal)')
    
    parser.add_argument('--special-env',
                       choices=list(SPECIAL_ENV_CONFIG.keys()),
                       help='特殊环境扫描模式')
    
    parser.add_argument('--no-discovery', action='store_true',
                       help='跳过主机发现扫描')
    
    parser.add_argument('--no-tcp', action='store_true',
                       help='跳过TCP扫描')
    
    parser.add_argument('--no-udp', action='store_true',
                       help='跳过UDP扫描')
    
    parser.add_argument('--tcp-only', action='store_true',
                       help='仅进行TCP扫描')
    
    parser.add_argument('--udp-only', action='store_true',
                       help='仅进行UDP扫描')
    
    parser.add_argument('-f', '--file',
                       default=SCAN_CONFIG['networks_file'],
                       help=f'网段文件路径 (默认: {SCAN_CONFIG["networks_file"]})')
    
    parser.add_argument('-o', '--output',
                       default=None,
                       help='输出文件路径 (默认: result_port_{port}.csv)')
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='详细输出')
    
    return parser.parse_args()

def main():
    """
    主函数
    """
    # 解析命令行参数
    args = parse_arguments()
    
    networks_file = args.file
    port = args.port
    output_file = args.output if args.output else f"result_port_{port}.csv"
    scan_mode = args.mode
    special_env = args.special_env
    
    print("=== Nmap 端口扫描工具 (增强版) ===")
    print(f"扫描端口: {port}")
    print(f"读取网段文件: {networks_file}")
    print(f"输出文件: {output_file}")
    
    if special_env:
        print(f"特殊环境模式: {special_env} - {SPECIAL_ENV_CONFIG[special_env]['description']}")
    else:
        print(f"扫描模式: {scan_mode}")
    
    print(f"支持扫描参数: TCP Connect(-sT), UDP(-sU), 主机发现(-sn)")
    print()
    
    # 读取网段信息
    networks = read_networks(networks_file)
    if not networks:
        print("没有找到有效的网段信息")
        sys.exit(1)
    
    print(f"找到 {len(networks)} 个网段:")
    for network in networks:
        print(f"  - {network}")
    print()
    
    all_results = []
    scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 对每个网段进行扫描
    for network in networks:
        print(f"\n开始扫描网段: {network}")
        
        # 1. 主机发现扫描 (如果启用)
        if not args.no_discovery:
            alive_hosts = run_host_discovery(network, special_env)
            if not alive_hosts:
                print("未发现活跃主机，跳过端口扫描")
                continue
            host_targets = ','.join(alive_hosts)
        else:
            print("跳过主机发现，直接扫描整个网段")
            host_targets = network
        
        # 2. 端口扫描
        print(f"对目标进行端口 {port} 扫描...")
        
        # TCP扫描
        if not args.no_tcp and not args.udp_only:
            tcp_nm = run_nmap_scan(host_targets, port, 'tcp', scan_mode, special_env)
            if not tcp_nm and not special_env:
                print("SYN扫描失败，尝试TCP Connect扫描...")
                tcp_nm = run_nmap_scan(host_targets, port, 'tcp', 'aggressive')
            
            if tcp_nm:
                tcp_results = parse_nmap_results(tcp_nm, port, 'tcp')
                for result in tcp_results:
                    result['scan_time'] = scan_time
                    result['network'] = network
                    all_results.append(result)
        
        # UDP扫描
        if not args.no_udp and not args.tcp_only:
            udp_nm = run_nmap_scan(host_targets, port, 'udp', scan_mode, special_env)
            if udp_nm:
                udp_results = parse_nmap_results(udp_nm, port, 'udp')
                for result in udp_results:
                    result['scan_time'] = scan_time
                    result['network'] = network
                    all_results.append(result)
    
    # 保存结果
    if all_results:
        save_to_csv(all_results, output_file)
        print(f"\n扫描完成！共发现 {len(all_results)} 个开放的端口 {port}")
    else:
        print(f"\n扫描完成，未发现开放的端口 {port}")
        # 创建空的CSV文件
        save_to_csv([], output_file)

if __name__ == '__main__':
    main()
    # 使用示例:
    # python3 nmap_dns_scanner.py --port 53                    # 扫描DNS端口
    # python3 nmap_dns_scanner.py --port 80 --tcp-only        # 扫描HTTP端口(仅TCP)
    # python3 nmap_dns_scanner.py --port 22 --mode stealth     # 扫描SSH端口(隐蔽模式)
    # python3 nmap_dns_scanner.py --port 443 --special-env fast_scan  # 扫描HTTPS端口(快速模式)