# Nmap 端口扫描工具

这是一个使用Python3编写的nmap端口扫描脚本，用于扫描指定网段的任意TCP和UDP端口。支持灵活的端口配置，可以扫描DNS、HTTP、SSH、HTTPS等各种服务端口。

## 功能特性

- 从`networks.txt`文件读取网段信息
- **支持扫描任意指定端口**（TCP和UDP协议）
- 同时扫描TCP和UDP端口（支持-sT、-sU参数）
- 主机发现扫描（-sn参数）
- 检测开放的服务端口
- 将扫描结果保存为CSV格式
- **动态生成输出文件名**（根据端口号）
- 支持多个网段批量扫描
- 多种扫描模式（隐蔽、快速、综合等）
- 特殊环境适配（防火墙绕过、静默扫描等）
- 灵活的命令行参数配置

## 文件说明

- `nmap_dns_scanner.py` - 主扫描脚本（使用python-nmap库）
- `config.py` - 扫描配置文件
- `networks.txt` - 网段配置文件（每行一个网段）
- `result_port_{port}.csv` - 扫描结果输出文件（根据端口号动态命名）
- `requirements.txt` - Python依赖包列表

## 使用方法

### 1. 安装依赖

首先确保系统已安装nmap：

```bash
# macOS
brew install nmap

# Ubuntu/Debian
sudo apt-get install nmap

# CentOS/RHEL
sudo yum install nmap
```

然后安装Python依赖包：

```bash
pip3 install -r requirements.txt
# 或者直接安装
pip3 install python-nmap
```

### 2. 配置网段

编辑`networks.txt`文件，每行添加一个要扫描的网段：

```
192.168.1.0/24
10.0.0.0/24
172.16.0.0/24
```

### 3. 运行扫描

#### 基本用法
```bash
# 默认扫描DNS端口（53）
python3 nmap_dns_scanner.py

# 扫描指定端口
python3 nmap_dns_scanner.py --port 80

# 查看帮助
python3 nmap_dns_scanner.py --help
```

#### 常用端口扫描示例
```bash
# 扫描DNS端口
python3 nmap_dns_scanner.py --port 53

# 扫描HTTP端口
python3 nmap_dns_scanner.py --port 80

# 扫描HTTPS端口
python3 nmap_dns_scanner.py --port 443

# 扫描SSH端口
python3 nmap_dns_scanner.py --port 22

# 扫描FTP端口
python3 nmap_dns_scanner.py --port 21
```

#### 扫描模式
```bash
# 隐蔽扫描模式（慢速，不易被发现）
python3 nmap_dns_scanner.py --port 80 --mode stealth

# 快速扫描模式
python3 nmap_dns_scanner.py --port 443 --mode aggressive

# 综合扫描模式
python3 nmap_dns_scanner.py --port 22 --mode comprehensive
```

#### 特殊环境模式
```bash
# 防火墙绕过模式
python3 nmap_dns_scanner.py --port 80 --special-env firewall_bypass

# 快速扫描模式
python3 nmap_dns_scanner.py --port 443 --special-env fast_scan

# 静默扫描模式
python3 nmap_dns_scanner.py --port 22 --special-env quiet_scan
```

#### 选择性扫描
```bash
# 仅TCP扫描
python3 nmap_dns_scanner.py --port 80 --tcp-only

# 仅UDP扫描
python3 nmap_dns_scanner.py --port 53 --udp-only

# 跳过主机发现
python3 nmap_dns_scanner.py --port 443 --no-discovery
```

#### 自定义文件
```bash
# 指定网段文件和输出文件
python3 nmap_dns_scanner.py --port 8080 -f custom_networks.txt -o custom_results.csv

# 使用默认输出文件名（自动根据端口号命名）
python3 nmap_dns_scanner.py --port 3306  # 输出到 result_port_3306.csv
```

### 4. 查看结果

扫描完成后，结果将保存在`result_port_{port}.csv`文件中，包含以下字段：

- `scan_time` - 扫描时间
- `network` - 扫描的网段
- `ip` - 主机IP地址
- `port` - 端口号（根据--port参数）
- `protocol` - 协议类型（tcp/udp）
- `state` - 端口状态（open）
- `service` - 服务名称

## 扫描模式说明

### 标准模式
- **normal**: 标准扫描模式（默认）
- **stealth**: 隐蔽扫描模式，使用慢速时序（-T2）
- **aggressive**: 快速扫描模式，使用TCP Connect扫描（-sT）
- **comprehensive**: 综合扫描模式，结合多种扫描技术

### 特殊环境模式
- **firewall_bypass**: 防火墙绕过模式，使用-Pn参数
- **fast_scan**: 快速扫描模式，使用高速率扫描
- **quiet_scan**: 静默扫描模式，使用分片和慢速扫描

## 支持的nmap参数

- **-sT**: TCP Connect扫描
- **-sU**: UDP扫描
- **-sn**: 主机发现扫描（Ping扫描）
- **-sS**: TCP SYN扫描（默认）
- **-Pn**: 跳过主机发现
- **-T0到-T5**: 时序模板
- **--open**: 仅显示开放端口

## 常用端口参考

| 端口 | 服务 | 协议 | 说明 |
|------|------|------|------|
| 21 | FTP | TCP | 文件传输协议 |
| 22 | SSH | TCP | 安全外壳协议 |
| 23 | Telnet | TCP | 远程登录协议 |
| 25 | SMTP | TCP | 简单邮件传输协议 |
| 53 | DNS | TCP/UDP | 域名系统 |
| 80 | HTTP | TCP | 超文本传输协议 |
| 110 | POP3 | TCP | 邮局协议版本3 |
| 143 | IMAP | TCP | 互联网消息访问协议 |
| 443 | HTTPS | TCP | 安全超文本传输协议 |
| 993 | IMAPS | TCP | 安全IMAP |
| 995 | POP3S | TCP | 安全POP3 |
| 3306 | MySQL | TCP | MySQL数据库 |
| 3389 | RDP | TCP | 远程桌面协议 |
| 5432 | PostgreSQL | TCP | PostgreSQL数据库 |
| 6379 | Redis | TCP | Redis数据库 |
| 8080 | HTTP-Alt | TCP | 备用HTTP端口 |

## 注意事项

1. 运行此脚本需要适当的网络权限
2. UDP扫描可能需要较长时间
3. 某些防火墙可能会阻止扫描
4. 请确保在授权的网络环境中使用此工具
5. 特殊环境模式适用于受限网络环境
6. 建议先使用stealth模式进行测试
7. **端口扫描应仅在授权的网络环境中进行**
8. 不同端口的扫描时间可能差异很大

## 命令行参数说明

```
-p, --port PORT          要扫描的端口号 (默认: 53)
-m, --mode MODE          扫描模式 (normal/stealth/aggressive/comprehensive)
--special-env ENV        特殊环境模式 (firewall_bypass/fast_scan/quiet_scan)
--no-discovery          跳过主机发现扫描
--no-tcp                跳过TCP扫描
--no-udp                跳过UDP扫描
--tcp-only              仅进行TCP扫描
--udp-only              仅进行UDP扫描
-f, --file FILE         网段文件路径 (默认: networks.txt)
-o, --output FILE       输出文件路径 (默认: result_port_{port}.csv)
-v, --verbose           详细输出
```

## 示例输出

**扫描HTTP端口（80）的结果示例：**
```csv
scan_time,network,ip,port,protocol,state,service
2024-01-01 12:00:00,192.168.1.0/24,192.168.1.1,80,tcp,open,http
2024-01-01 12:00:00,192.168.1.0/24,192.168.1.10,80,tcp,open,http
```

**扫描DNS端口（53）的结果示例：**
```csv
scan_time,network,ip,port,protocol,state,service
2024-01-01 12:00:00,192.168.1.0/24,192.168.1.1,53,tcp,open,domain
2024-01-01 12:00:00,192.168.1.0/24,192.168.1.1,53,udp,open,domain
```