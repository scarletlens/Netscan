```text
 _   _      _   ____                                 
| \ | | ___| |_/ ___|  ___ __ _ _ __  _ __   ___ _ __
|  \| |/ _ \ __\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
| |\  |  __/ |_ ___) | (_| (_| | | | | | | |  __/ |   
|_| \_|\___|\__|____/ \___\__,_|_| |_|_| |_|\___|_|   
```

# Netscan

`Netscan` 是一个面向授权场景的中文 CLI / TUI 扫描工具，用于：

- 资产发现
- 常见 Web 端口探测
- HTTP/HTTPS 页面采集
- 风险路径扫描
- 被动安全检查
- 结果归档与历史回看

## 当前能力

- 输入域名、IP、`IP:端口`、URL 直接扫描
- 支持端口范围，例如 `1-1024`、`80,443,8000-9000`
- 常见 Web 端口自动发现
- 站内链接递归采集
- 登录页、后台页、接口文档、调试页、敏感文件路径扫描
- 风险分级：`high / medium / low / info`
- 结果、风险、归档中文界面
- 每次扫描自动生成归档

## 安全边界

本项目仅用于你拥有或明确获授权的环境。

当前实现聚焦于：

- 发现
- 采集
- 枚举
- 被动检查
- 风险线索整理

不包含利用、爆破、绕过认证或自动攻击功能。

## 安装与运行

当前项目基于 Python 3 运行，不依赖额外第三方库。

直接运行：

```bash
python3 -m netscan scan --target example.com
```

打开中文交互控制台：

```bash
python3 -m netscan console
```

一键启动控制台：

```bash
./run.sh
```

## 常见用法

扫描一个目标：

```bash
python3 -m netscan scan --target example.com --ports common
```

扫描指定端口范围：

```bash
python3 -m netscan scan --target example.com --ports 1-1024
python3 -m netscan scan --target 10.0.0.5 --ports 80,443,8000-9000
```

扫描完整 URL：

```bash
python3 -m netscan scan --target https://example.com/login
```

控制站内采集深度：

```bash
python3 -m netscan scan --target example.com --ports common --crawl-depth 1 --max-pages 20
```

输出 JSON：

```bash
python3 -m netscan scan --target example.com --json
```

## 控制台使用

启动：

```bash
./run.sh
```

输入框支持直接输入：

```text
example.com
192.168.1.10
192.168.1.10:8080
example.com 1-1024
10.0.0.5 80,443,8000-9000
https://example.com/login
```

规则：

- 输入域名或 IP：默认扫描一组常见 Web 端口
- 输入 `主机:端口`：只扫描这个端口
- 输入 `目标 端口范围`：按范围扫描
- 输入完整 URL：直接按 URL 探测

高级命令：

```text
/筛选 200
/筛选 login
/加载 latest
/归档
/帮助
/退出
```

标签页切换：

- `Tab`：下一个标签页
- `Shift+Tab`：上一个标签页
- `ESC`：退出控制台

## 扫描内容

### 1. 端口与服务

- 开放端口识别
- 常见服务名猜测
- HTTP / HTTPS 与非 HTTP 端口区分

### 2. 页面与站内发现

- 首页探测
- 标题提取
- 重定向识别
- 站内链接提取
- 递归页面采集

### 3. 风险路径扫描

登录入口：

- `/login`
- `/signin`
- `/sign-in`
- `/user/login`
- `/auth/login`
- `/account/login`
- `/member/login`
- `/passport/login`
- `/admin/login`

后台入口：

- `/admin`
- `/dashboard`
- `/console`
- `/manage`
- `/manager`
- `/backend`
- `/system`
- `/cpanel`
- `/admin/index`

接口文档：

- `/swagger`
- `/swagger-ui`
- `/swagger-ui.html`
- `/openapi.json`
- `/api-docs`
- `/v2/api-docs`
- `/v3/api-docs`
- `/redoc`

调试与监控：

- `/actuator`
- `/actuator/health`
- `/actuator/env`
- `/phpinfo.php`
- `/server-status`
- `/debug`
- `/metrics`

敏感文件：

- `/.env`
- `/.git/config`
- `/config.js`
- `/backup.zip`
- `/backup.tar.gz`
- `/dump.sql`
- `/.DS_Store`

### 4. 被动安全检查

- 缺少 `CSP`
- 缺少 `X-Frame-Options`
- 缺少 `X-Content-Type-Options`
- 缺少 `HSTS`
- `Server` 头暴露
- Cookie 缺少 `Secure`
- Cookie 缺少 `HttpOnly`
- 重定向链提示
- 风险等级与复查建议

## 结果展示

文本模式和控制台里会显示：

- 可访问端点
- 开放端口 / 服务
- 命中的风险路径
- 风险等级
- 风险详情

命中的风险路径现在会单独显示为记录，例如：

- `/robots.txt`
- `/login`
- `/admin`
- `/swagger`

## 归档

每次扫描都会写入：

- `archives/<扫描对象>-<run-id>/summary.json`
- `archives/<扫描对象>-<run-id>/results.ndjson`

例如：

```text
archives/example.com-run-20260410T100748Z/
```

## GitHub 上传

项目已附带 `.gitignore`，默认忽略：

- `archives/`
- `__pycache__/`
- `*.pyc`
- `.DS_Store`
- `.venv/`
- `venv/`
- `.idea/`
- `.vscode/`

这样本地扫描记录、缓存和系统文件不会被提交到 GitHub。

## 帮助命令

查看扫描参数：

```bash
python3 -m netscan scan --help
```

查看控制台：

```bash
python3 -m netscan console --help
```
