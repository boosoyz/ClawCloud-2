"""
ClawCloud 自动登录脚本 - 修复版
- 支持 Hysteria2 代理（用于通过人机验证）
- 自动检测区域跳转（如 ap-southeast-1.console.claw.cloud）
- 正确处理 OAuth callback 页面
- 等待设备验证批准（30秒）
- 每次登录后自动更新 Cookie
- Telegram 通知
"""

import os
import sys
import time
import base64
import re
import json
import subprocess
import signal
import requests
from urllib.parse import urlparse, parse_qs, unquote
from playwright.sync_api import sync_playwright

# ==================== 配置 ====================
# 固定登录入口，OAuth后会自动跳转到实际区域
LOGIN_ENTRY_URL = "https://console.run.claw.cloud"
SIGNIN_URL = f"{LOGIN_ENTRY_URL}/signin"
DEVICE_VERIFY_WAIT = 30  # Mobile验证 默认等 30 秒
TWO_FACTOR_WAIT = int(os.environ.get("TWO_FACTOR_WAIT", "120"))  # 2FA验证 默认等 120 秒

# 代理配置
LOCAL_PROXY_PORT = 51080  # 本地 SOCKS5 代理端口
LOCAL_HTTP_PORT = 51081   # 本地 HTTP 代理端口


class Hysteria2Proxy:
    """Hysteria2 代理管理器"""
    
    def __init__(self):
        self.hy2_url = os.environ.get('PROXY_HY2', '').strip()
        self.process = None
        self.config_file = '/tmp/hy2_config.yaml'
        self.enabled = False
        
        if self.hy2_url:
            print("✅ 检测到 Hysteria2 代理配置")
            self.enabled = True
        else:
            print("ℹ️ 未配置 Hysteria2 代理，将直接连接")
    
    def parse_url(self):
        """
        解析 Hysteria2 URL
        格式: hysteria2://password@host:port?sni=xxx&alpn=xxx&insecure=1#name
        """
        if not self.hy2_url:
            return None
        
        try:
            # 移除 hysteria2:// 前缀
            url = self.hy2_url
            if url.startswith('hysteria2://'):
                url = url[12:]
            elif url.startswith('hy2://'):
                url = url[6:]
            
            # 分离 fragment（#后面的名称）
            if '#' in url:
                url, _ = url.rsplit('#', 1)
            
            # 分离查询参数
            params = {}
            if '?' in url:
                url, query = url.split('?', 1)
                params = parse_qs(query)
            
            # 解析 password@host:port
            if '@' in url:
                password, host_port = url.rsplit('@', 1)
                password = unquote(password)
            else:
                password = ''
                host_port = url
            
            # 解析 host:port
            if ':' in host_port:
                host, port = host_port.rsplit(':', 1)
                port = int(port)
            else:
                host = host_port
                port = 443
            
            config = {
                'server': f"{host}:{port}",
                'auth': password,
                'tls': {
                    'sni': params.get('sni', [host])[0],
                    'insecure': params.get('insecure', ['0'])[0] == '1'
                },
                'socks5': {
                    'listen': f"127.0.0.1:{LOCAL_PROXY_PORT}"
                },
                'http': {
                    'listen': f"127.0.0.1:{LOCAL_HTTP_PORT}"
                }
            }
            
            # 添加 ALPN（如果有）
            if 'alpn' in params:
                alpn = params['alpn'][0]
                config['tls']['alpn'] = alpn.split(',')
            
            print(f"  📍 服务器: {host}:{port}")
            print(f"  🔐 认证: {password[:4]}...{password[-4:] if len(password) > 8 else '***'}")
            print(f"  🌐 SNI: {config['tls']['sni']}")
            print(f"  🔓 跳过验证: {config['tls']['insecure']}")
            
            return config
            
        except Exception as e:
            print(f"❌ 解析 Hysteria2 URL 失败: {e}")
            return None
    
    def generate_config(self, config):
        """生成 Hysteria2 配置文件"""
        import yaml
        
        with open(self.config_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        print(f"✅ 已生成配置文件: {self.config_file}")
        return self.config_file
    
    def generate_config_json(self, config):
        """生成 Hysteria2 JSON 配置文件（备选）"""
        json_config = {
            "server": config['server'],
            "auth": config['auth'],
            "tls": config['tls'],
            "socks5": config['socks5'],
            "http": config['http']
        }
        
        json_file = '/tmp/hy2_config.json'
        with open(json_file, 'w') as f:
            json.dump(json_config, f, indent=2)
        
        return json_file
    
    def start(self):
        """启动 Hysteria2 客户端"""
        if not self.enabled:
            return True
        
        config = self.parse_url()
        if not config:
            print("❌ 无法解析代理配置")
            return False
        
        # 尝试使用 YAML 配置
        try:
            import yaml
            config_file = self.generate_config(config)
        except ImportError:
            print("⚠️ PyYAML 未安装，使用 JSON 配置")
            config_file = self.generate_config_json(config)
        
        try:
            print("🚀 启动 Hysteria2 代理...")
            
            self.process = subprocess.Popen(
                ['hysteria', 'client', '-c', config_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )
            
            time.sleep(3)
            
            if self.process.poll() is not None:
                stdout, stderr = self.process.communicate()
                print(f"❌ Hysteria2 启动失败")
                print(f"  stdout: {stdout.decode()}")
                print(f"  stderr: {stderr.decode()}")
                return False
            
            if self.test_proxy():
                print(f"✅ Hysteria2 代理已启动")
                print(f"  SOCKS5: 127.0.0.1:{LOCAL_PROXY_PORT}")
                print(f"  HTTP: 127.0.0.1:{LOCAL_HTTP_PORT}")
                return True
            else:
                print("❌ 代理测试失败")
                self.stop()
                return False
                
        except FileNotFoundError:
            print("❌ 找不到 hysteria 命令，请确保已安装")
            return False
        except Exception as e:
            print(f"❌ 启动 Hysteria2 失败: {e}")
            return False
    
    def test_proxy(self, retries=3):
        """测试代理是否可用"""
        for i in range(retries):
            try:
                proxies = {
                    'http': f'socks5://127.0.0.1:{LOCAL_PROXY_PORT}',
                    'https': f'socks5://127.0.0.1:{LOCAL_PROXY_PORT}'
                }
                
                r = requests.get(
                    'https://api.ipify.org?format=json',
                    proxies=proxies,
                    timeout=10
                )
                
                if r.status_code == 200:
                    ip = r.json().get('ip', 'unknown')
                    print(f"✅ 代理测试成功，出口 IP: {ip}")
                    return True
                    
            except Exception as e:
                print(f"  代理测试 {i+1}/{retries} 失败: {e}")
                time.sleep(2)
        
        return False
    
    def stop(self):
        """停止 Hysteria2 客户端"""
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.wait(timeout=5)
                print("✅ Hysteria2 已停止")
            except Exception as e:
                print(f"⚠️ 停止 Hysteria2 时出错: {e}")
                try:
                    self.process.kill()
                except:
                    pass
    
    def get_playwright_proxy(self):
        """获取 Playwright 代理配置"""
        if not self.enabled:
            return None
        
        return {
            'server': f'socks5://127.0.0.1:{LOCAL_PROXY_PORT}'
        }


class Telegram:
    """Telegram 通知"""
    
    def __init__(self, proxy=None):
        self.token = os.environ.get('TG_BOT_TOKEN')
        self.chat_id = os.environ.get('TG_CHAT_ID')
        self.ok = bool(self.token and self.chat_id)
        self.proxy = proxy
    
    def _get_proxies(self):
        """获取请求代理配置"""
        if self.proxy and self.proxy.enabled:
            return {
                'http': f'socks5://127.0.0.1:{LOCAL_PROXY_PORT}',
                'https': f'socks5://127.0.0.1:{LOCAL_PROXY_PORT}'
            }
        return None
    
    def send(self, msg):
        if not self.ok:
            return
        try:
            requests.post(
                f"https://api.telegram.org/bot{self.token}/sendMessage",
                data={"chat_id": self.chat_id, "text": msg, "parse_mode": "HTML"},
                timeout=30,
                proxies=self._get_proxies()
            )
        except:
            try:
                requests.post(
                    f"https://api.telegram.org/bot{self.token}/sendMessage",
                    data={"chat_id": self.chat_id, "text": msg, "parse_mode": "HTML"},
                    timeout=30
                )
            except:
                pass
    
    def photo(self, path, caption=""):
        if not self.ok or not os.path.exists(path):
            return
        try:
            with open(path, 'rb') as f:
                requests.post(
                    f"https://api.telegram.org/bot{self.token}/sendPhoto",
                    data={"chat_id": self.chat_id, "caption": caption[:1024]},
                    files={"photo": f},
                    timeout=60,
                    proxies=self._get_proxies()
                )
        except:
            try:
                with open(path, 'rb') as f:
                    requests.post(
                        f"https://api.telegram.org/bot{self.token}/sendPhoto",
                        data={"chat_id": self.chat_id, "caption": caption[:1024]},
                        files={"photo": f},
                        timeout=60
                    )
            except:
                pass
    
    def flush_updates(self):
        """刷新 offset 到最新，避免读到旧消息"""
        if not self.ok:
            return 0
        try:
            r = requests.get(
                f"https://api.telegram.org/bot{self.token}/getUpdates",
                params={"timeout": 0},
                timeout=10,
                proxies=self._get_proxies()
            )
            data = r.json()
            if data.get("ok") and data.get("result"):
                return data["result"][-1]["update_id"] + 1
        except:
            pass
        return 0
    
    def wait_code(self, timeout=120):
        """等待你在 TG 里发 /code 123456"""
        if not self.ok:
            return None
        
        offset = self.flush_updates()
        deadline = time.time() + timeout
        pattern = re.compile(r"^/code\s+(\d{6,8})$")
        
        while time.time() < deadline:
            try:
                r = requests.get(
                    f"https://api.telegram.org/bot{self.token}/getUpdates",
                    params={"timeout": 20, "offset": offset},
                    timeout=30,
                    proxies=self._get_proxies()
                )
                data = r.json()
                if not data.get("ok"):
                    time.sleep(2)
                    continue
                
                for upd in data.get("result", []):
                    offset = upd["update_id"] + 1
                    msg = upd.get("message") or {}
                    chat = msg.get("chat") or {}
                    if str(chat.get("id")) != str(self.chat_id):
                        continue
                    
                    text = (msg.get("text") or "").strip()
                    m = pattern.match(text)
                    if m:
                        return m.group(1)
            
            except Exception:
                pass
            
            time.sleep(2)
        
        return None


class SecretUpdater:
    """GitHub Secret 更新器"""
    
    def __init__(self):
        self.token = os.environ.get('REPO_TOKEN')
        self.repo = os.environ.get('GITHUB_REPOSITORY')
        self.ok = bool(self.token and self.repo)
        if self.ok:
            print("✅ Secret 自动更新已启用")
        else:
            print("⚠️ Secret 自动更新未启用（需要 REPO_TOKEN）")
    
    def update(self, name, value):
        if not self.ok:
            return False
        try:
            from nacl import encoding, public
            
            headers = {
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            r = requests.get(
                f"https://api.github.com/repos/{self.repo}/actions/secrets/public-key",
                headers=headers, timeout=30
            )
            if r.status_code != 200:
                return False
            
            key_data = r.json()
            pk = public.PublicKey(key_data['key'].encode(), encoding.Base64Encoder())
            encrypted = public.SealedBox(pk).encrypt(value.encode())
            
            r = requests.put(
                f"https://api.github.com/repos/{self.repo}/actions/secrets/{name}",
                headers=headers,
                json={"encrypted_value": base64.b64encode(encrypted).decode(), "key_id": key_data['key_id']},
                timeout=30
            )
            return r.status_code in [201, 204]
        except Exception as e:
            print(f"更新 Secret 失败: {e}")
            return False

class AutoLogin:
    """自动登录"""
    
    def __init__(self):
        self.username = os.environ.get('GH_USERNAME')
        self.password = os.environ.get('GH_PASSWORD')
        self.gh_session = os.environ.get('GH_SESSION', '').strip()
        
        # 初始化代理
        self.proxy = Hysteria2Proxy()
        
        self.tg = Telegram(proxy=self.proxy)
        self.secret = SecretUpdater()
        self.shots = []
        self.logs = []
        self.n = 0
        
        # 区域相关
        self.detected_region = None
        self.region_base_url = None
        
    def log(self, msg, level="INFO"):
        icons = {"INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "WARN": "⚠️", "STEP": "🔹"}
        line = f"{icons.get(level, '•')} {msg}"
        print(line)
        self.logs.append(line)
    
    def shot(self, page, name):
        self.n += 1
        f = f"{self.n:02d}_{name}.png"
        try:
            page.screenshot(path=f)
            self.shots.append(f)
        except:
            pass
        return f
    
    def click(self, page, sels, desc=""):
        for s in sels:
            try:
                el = page.locator(s).first
                if el.is_visible(timeout=3000):
                    el.click()
                    self.log(f"已点击: {desc}", "SUCCESS")
                    return True
            except:
                pass
        return False
    
    def detect_region(self, url):
        """从 URL 中检测区域信息"""
        try:
            parsed = urlparse(url)
            host = parsed.netloc
            
            # 检查格式: {region}.run.claw.cloud 或 {region}.console.claw.cloud
            for suffix in ['.run.claw.cloud', '.console.claw.cloud']:
                if host.endswith(suffix):
                    region = host.replace(suffix, '')
                    if region and region not in ['console', 'run', 'www']:
                        self.detected_region = region
                        self.region_base_url = f"https://{host}"
                        self.log(f"检测到区域: {region}", "SUCCESS")
                        return region
            
            # 尝试从路径提取
            path = parsed.path
            region_match = re.search(r'/(?:region|r)/([a-z]+-[a-z]+-\d+)', path)
            if region_match:
                region = region_match.group(1)
                self.detected_region = region
                self.region_base_url = f"https://{region}.run.claw.cloud"
                self.log(f"从路径检测到区域: {region}", "SUCCESS")
                return region
            
            # 使用当前域名
            self.region_base_url = f"{parsed.scheme}://{parsed.netloc}"
            return None
            
        except Exception as e:
            self.log(f"区域检测异常: {e}", "WARN")
            return None
    
    def get_base_url(self):
        """获取当前应该使用的基础 URL"""
        if self.region_base_url:
            return self.region_base_url
        return LOGIN_ENTRY_URL
    
    def get_session(self, context):
        """提取 Session Cookie"""
        try:
            for c in context.cookies():
                if c['name'] == 'user_session' and 'github' in c.get('domain', ''):
                    return c['value']
        except:
            pass
        return None
    
    def save_cookie(self, value):
        """保存新 Cookie"""
        if not value:
            return
        
        self.log(f"新 Cookie: {value[:15]}...{value[-8:]}", "SUCCESS")
        
        if self.secret.update('GH_SESSION', value):
            self.log("已自动更新 GH_SESSION", "SUCCESS")
            self.tg.send("🔑 <b>Cookie 已自动更新</b>\n\nGH_SESSION 已保存")
        else:
            self.tg.send(f"""🔑 <b>新 Cookie</b>

请更新 Secret <b>GH_SESSION</b>:
<code>{value}</code>""")
            self.log("已通过 Telegram 发送 Cookie", "SUCCESS")
    
    def wait_device(self, page):
        """等待设备验证"""
        self.log(f"需要设备验证，等待 {DEVICE_VERIFY_WAIT} 秒...", "WARN")
        self.shot(page, "设备验证")
        
        self.tg.send(f"""⚠️ <b>需要设备验证</b>

请在 {DEVICE_VERIFY_WAIT} 秒内批准：
1️⃣ 检查邮箱点击链接
2️⃣ 或在 GitHub App 批准""")
        
        if self.shots:
            self.tg.photo(self.shots[-1], "设备验证页面")
        
        for i in range(DEVICE_VERIFY_WAIT):
            time.sleep(1)
            if i % 5 == 0:
                self.log(f"  等待... ({i}/{DEVICE_VERIFY_WAIT}秒)")
                url = page.url
                if 'verified-device' not in url and 'device-verification' not in url:
                    self.log("设备验证通过！", "SUCCESS")
                    self.tg.send("✅ <b>设备验证通过</b>")
                    return True
                try:
                    page.reload(timeout=10000)
                    page.wait_for_load_state('networkidle', timeout=10000)
                except:
                    pass
        
        if 'verified-device' not in page.url:
            return True
        
        self.log("设备验证超时", "ERROR")
        self.tg.send("❌ <b>设备验证超时</b>")
        return False
    
    def wait_two_factor_mobile(self, page):
        """等待 GitHub Mobile 两步验证批准"""
        self.log(f"需要两步验证（GitHub Mobile），等待 {TWO_FACTOR_WAIT} 秒...", "WARN")
        
        shot = self.shot(page, "两步验证_mobile")
        self.tg.send(f"""⚠️ <b>需要两步验证（GitHub Mobile）</b>

请打开手机 GitHub App 批准本次登录（会让你确认一个数字）。
等待时间：{TWO_FACTOR_WAIT} 秒""")
        if shot:
            self.tg.photo(shot, "两步验证页面（数字在图里）")
        
        for i in range(TWO_FACTOR_WAIT):
            time.sleep(1)
            
            url = page.url
            
            if "github.com/sessions/two-factor/" not in url:
                self.log("两步验证通过！", "SUCCESS")
                self.tg.send("✅ <b>两步验证通过</b>")
                return True
            
            if "github.com/login" in url:
                self.log("两步验证后回到了登录页，需重新登录", "ERROR")
                return False
            
            if i % 10 == 0 and i != 0:
                self.log(f"  等待... ({i}/{TWO_FACTOR_WAIT}秒)")
                shot = self.shot(page, f"两步验证_{i}s")
                if shot:
                    self.tg.photo(shot, f"两步验证页面（第{i}秒）")
            
            if i % 30 == 0 and i != 0:
                try:
                    page.reload(timeout=30000)
                    page.wait_for_load_state('domcontentloaded', timeout=30000)
                except:
                    pass
        
        self.log("两步验证超时", "ERROR")
        self.tg.send("❌ <b>两步验证超时</b>")
        return False
    
    def handle_2fa_code_input(self, page):
        """处理 TOTP 验证码输入"""
        self.log("需要输入验证码", "WARN")
        shot = self.shot(page, "两步验证_code")
        
        try:
            more_options = [
                'a:has-text("Use an authentication app")',
                'a:has-text("Enter a code")',
                'button:has-text("Use an authentication app")',
                '[href*="two-factor/app"]'
            ]
            for sel in more_options:
                try:
                    el = page.locator(sel).first
                    if el.is_visible(timeout=2000):
                        el.click()
                        time.sleep(2)
                        page.wait_for_load_state('networkidle', timeout=15000)
                        self.log("已切换到验证码输入页面", "SUCCESS")
                        shot = self.shot(page, "两步验证_code_切换后")
                        break
                except:
                    pass
        except:
            pass
        
        self.tg.send(f"""🔐 <b>需要验证码登录</b>

请在 Telegram 里发送：
<code>/code 你的6位验证码</code>

等待时间：{TWO_FACTOR_WAIT} 秒""")
        if shot:
            self.tg.photo(shot, "两步验证页面")
        
        self.log(f"等待验证码（{TWO_FACTOR_WAIT}秒）...", "WARN")
        code = self.tg.wait_code(timeout=TWO_FACTOR_WAIT)
        
        if not code:
            self.log("等待验证码超时", "ERROR")
            self.tg.send("❌ <b>等待验证码超时</b>")
            return False
        
        self.log("收到验证码，正在填入...", "SUCCESS")
        self.tg.send("✅ 收到验证码，正在填入...")
        
        selectors = [
            'input[autocomplete="one-time-code"]',
            'input[name="app_otp"]',
            'input[name="otp"]',
            'input#app_totp',
            'input#otp',
            'input[inputmode="numeric"]'
        ]
        
        for sel in selectors:
            try:
                el = page.locator(sel).first
                if el.is_visible(timeout=2000):
                    el.fill(code)
                    self.log(f"已填入验证码", "SUCCESS")
                    time.sleep(1)
                    
                    submitted = False
                    verify_btns = [
                        'button:has-text("Verify")',
                        'button[type="submit"]',
                        'input[type="submit"]'
                    ]
                    for btn_sel in verify_btns:
                        try:
                            btn = page.locator(btn_sel).first
                            if btn.is_visible(timeout=1000):
                                btn.click()
                                submitted = True
                                self.log("已点击 Verify 按钮", "SUCCESS")
                                break
                        except:
                            pass
                    
                    if not submitted:
                        page.keyboard.press("Enter")
                        self.log("已按 Enter 提交", "SUCCESS")
                    
                    time.sleep(3)
                    page.wait_for_load_state('networkidle', timeout=30000)
                    self.shot(page, "验证码提交后")
                    
                    if "github.com/sessions/two-factor/" not in page.url:
                        self.log("验证码验证通过！", "SUCCESS")
                        self.tg.send("✅ <b>验证码验证通过</b>")
                        return True
                    else:
                        self.log("验证码可能错误", "ERROR")
                        self.tg.send("❌ <b>验证码可能错误，请检查后重试</b>")
                        return False
            except:
                pass
        
        self.log("没找到验证码输入框", "ERROR")
        self.tg.send("❌ <b>没找到验证码输入框</b>")
        return False
    
    def login_github(self, page, context):
        """登录 GitHub"""
        self.log("登录 GitHub...", "STEP")
        self.shot(page, "github_登录页")
        
        try:
            page.locator('input[name="login"]').fill(self.username)
            page.locator('input[name="password"]').fill(self.password)
            self.log("已输入凭据")
        except Exception as e:
            self.log(f"输入失败: {e}", "ERROR")
            return False
        
        self.shot(page, "github_已填写")
        
        try:
            page.locator('input[type="submit"], button[type="submit"]').first.click()
        except:
            pass
        
        time.sleep(3)
        page.wait_for_load_state('networkidle', timeout=30000)
        self.shot(page, "github_登录后")
        
        url = page.url
        self.log(f"当前: {url}")
        
        # 设备验证
        if 'verified-device' in url or 'device-verification' in url:
            if not self.wait_device(page):
                return False
            time.sleep(2)
            page.wait_for_load_state('networkidle', timeout=30000)
            self.shot(page, "验证后")
        
        # 2FA
        if 'two-factor' in page.url:
            self.log("需要两步验证！", "WARN")
            self.shot(page, "两步验证")
            
            if 'two-factor/mobile' in page.url:
                if not self.wait_two_factor_mobile(page):
                    return False
                try:
                    page.wait_for_load_state('networkidle', timeout=30000)
                    time.sleep(2)
                except:
                    pass
            else:
                if not self.handle_2fa_code_input(page):
                    return False
                try:
                    page.wait_for_load_state('networkidle', timeout=30000)
                    time.sleep(2)
                except:
                    pass
        
        # 错误检查
        try:
            err = page.locator('.flash-error').first
            if err.is_visible(timeout=2000):
                self.log(f"错误: {err.inner_text()}", "ERROR")
                return False
        except:
            pass
        
        return True
    
    def oauth(self, page):
        """处理 OAuth"""
        if 'github.com/login/oauth/authorize' in page.url:
            self.log("处理 OAuth...", "STEP")
            self.shot(page, "oauth")
            self.click(page, ['button[name="authorize"]', 'button:has-text("Authorize")'], "授权")
            time.sleep(3)
            page.wait_for_load_state('networkidle', timeout=30000)
    
    def is_valid_console_page(self, url):
        """
        检查 URL 是否是有效的控制台页面（非中间页面）
        """
        if 'claw.cloud' not in url:
            return False
        
        # 中间页面列表
        intermediate_patterns = [
            '/callback',
            '/signin',
            '/login',
            '/auth',
            '/oauth',
            '/redirect'
        ]
        
        url_lower = url.lower()
        for pattern in intermediate_patterns:
            if pattern in url_lower:
                return False
        
        return True
    
    def wait_redirect(self, page, wait=90):
        """
        等待重定向到真正的控制台页面
        修复：排除 callback 等中间页面
        """
        self.log("等待重定向...", "STEP")
        
        last_url = ""
        stable_count = 0
        
        for i in range(wait):
            try:
                url = page.url
                
                # 检查是否到达有效的控制台页面
                if self.is_valid_console_page(url):
                    self.log(f"重定向成功！", "SUCCESS")
                    self.log(f"最终 URL: {url}", "INFO")
                    self.detect_region(url)
                    return True
                
                # 在 claw.cloud 但还在中间页面
                if 'claw.cloud' in url:
                    if '/callback' in url.lower():
                        if i % 3 == 0:
                            self.log(f"  OAuth callback 处理中... ({i}秒)")
                        # 等待页面自动跳转
                        try:
                            page.wait_for_url(
                                lambda u: 'callback' not in u.lower(),
                                timeout=5000
                            )
                        except:
                            pass
                    elif '/signin' in url.lower() or '/login' in url.lower():
                        if i % 5 == 0:
                            self.log(f"  还在登录页... ({i}秒)")
                
                # GitHub OAuth 授权页面
                if 'github.com/login/oauth/authorize' in url:
                    self.oauth(page)
                
                # URL 稳定性检查（防止无限等待）
                if url == last_url:
                    stable_count += 1
                    if stable_count >= 10 and 'claw.cloud' in url:
                        # URL 稳定了10秒，尝试刷新
                        self.log("页面似乎卡住了，尝试刷新...", "WARN")
                        try:
                            page.reload(timeout=15000)
                            page.wait_for_load_state('networkidle', timeout=15000)
                        except:
                            pass
                        stable_count = 0
                else:
                    stable_count = 0
                    last_url = url
                
                time.sleep(1)
                if i % 10 == 0 and i > 0:
                    self.log(f"  等待... ({i}秒) - {url[:60]}...")
                    self.shot(page, f"等待_{i}s")
                    
            except Exception as e:
                self.log(f"  等待异常: {e}", "WARN")
                time.sleep(1)
        
        # 超时后最终检查
        final_url = page.url
        self.log(f"等待超时，最终 URL: {final_url}", "WARN")
        self.shot(page, "重定向超时")
        
        if self.is_valid_console_page(final_url):
            self.log("最终检查通过", "SUCCESS")
            self.detect_region(final_url)
            return True
        
        self.log("重定向失败", "ERROR")
        return False
    
    def keepalive(self, page):
        """
        保活 - 验证是否真正登录成功
        修复：检查是否被重定向回登录页
        """
        self.log("保活验证...", "STEP")
        
        base_url = self.get_base_url()
        self.log(f"使用区域 URL: {base_url}", "INFO")
        
        pages_to_visit = [
            (f"{base_url}/", "控制台首页"),
            (f"{base_url}/apps", "应用列表"),
        ]
        
        login_verified = False
        
        for url, name in pages_to_visit:
            try:
                self.log(f"访问: {name}...", "INFO")
                page.goto(url, timeout=30000)
                page.wait_for_load_state('networkidle', timeout=20000)
                time.sleep(3)
                
                current_url = page.url
                self.log(f"  实际 URL: {current_url}", "INFO")
                
                # 检查是否被重定向到登录页
                if '/signin' in current_url.lower() or '/login' in current_url.lower():
                    self.log(f"访问 {name} 被重定向到登录页！", "ERROR")
                    self.shot(page, f"重定向到登录_{name}")
                    continue
                
                # 检查页面内容是否有登录相关元素
                try:
                    # 如果页面有 GitHub 登录按钮，说明没登录成功
                    github_btn = page.locator('button:has-text("GitHub"), a:has-text("GitHub")').first
                    if github_btn.is_visible(timeout=2000):
                        # 检查是否在登录页面
                        if 'signin' in current_url.lower() or page.locator('text=Sign in').first.is_visible(timeout=1000):
                            self.log(f"页面显示登录界面，登录可能失败", "ERROR")
                            self.shot(page, f"登录界面_{name}")
                            continue
                except:
                    pass
                
                self.log(f"已验证: {name}", "SUCCESS")
                login_verified = True
                
                # 更新区域检测
                if 'claw.cloud' in current_url:
                    self.detect_region(current_url)
                
            except Exception as e:
                self.log(f"访问 {name} 失败: {e}", "WARN")
        
        self.shot(page, "保活完成")
        
        if not login_verified:
            self.log("保活验证失败 - 未能确认登录成功", "ERROR")
            return False
        
        self.log("保活验证成功", "SUCCESS")
        return True

    def notify(self, ok, err=""):
        """发送通知"""
        if not self.tg.ok:
            return
        
        region_info = f"\n<b>区域:</b> {self.detected_region or '默认'}" if self.detected_region else ""
        proxy_info = "\n<b>代理:</b> Hysteria2 ✅" if self.proxy.enabled else ""
        
        msg = f"""<b>🤖 ClawCloud 自动登录</b>

<b>状态:</b> {"✅ 成功" if ok else "❌ 失败"}
<b>用户:</b> {self.username}{region_info}{proxy_info}
<b>时间:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}"""
        
        if err:
            msg += f"\n<b>错误:</b> {err}"
        
        msg += "\n\n<b>日志:</b>\n" + "\n".join(self.logs[-8:])
        
        self.tg.send(msg)
        
        # 发送截图
        if self.shots:
            if not ok:
                # 失败时发送最后几张截图
                for s in self.shots[-3:]:
                    self.tg.photo(s, s)
            else:
                # 成功时只发送最后一张
                self.tg.photo(self.shots[-1], "登录成功")
    
    def run(self):
        """主运行方法"""
        print("\n" + "="*50)
        print("🚀 ClawCloud 自动登录 - 修复版")
        print("="*50 + "\n")
        
        self.log(f"用户名: {self.username}")
        self.log(f"Session: {'有' if self.gh_session else '无'}")
        self.log(f"密码: {'有' if self.password else '无'}")
        self.log(f"代理: {'Hysteria2' if self.proxy.enabled else '无'}")
        self.log(f"登录入口: {LOGIN_ENTRY_URL}")
        
        if not self.username or not self.password:
            self.log("缺少凭据", "ERROR")
            self.notify(False, "凭据未配置")
            sys.exit(1)
        
        # 启动代理
        if self.proxy.enabled:
            if not self.proxy.start():
                self.log("代理启动失败，继续尝试直连...", "WARN")
                self.proxy.enabled = False
        
        try:
            with sync_playwright() as p:
                # 配置浏览器启动参数
                browser_args = ['--no-sandbox', '--disable-blink-features=AutomationControlled']
                
                # 获取代理配置
                proxy_config = self.proxy.get_playwright_proxy()
                
                browser = p.chromium.launch(
                    headless=True,
                    args=browser_args
                )
                
                # 创建带代理的上下文
                context_options = {
                    'viewport': {'width': 1920, 'height': 1080},
                    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                }
                
                if proxy_config:
                    context_options['proxy'] = proxy_config
                    self.log(f"Playwright 使用代理: {proxy_config['server']}", "INFO")
                
                context = browser.new_context(**context_options)
                page = context.new_page()
                
                try:
                    # 预加载 Cookie
                    if self.gh_session:
                        try:
                            context.add_cookies([
                                {'name': 'user_session', 'value': self.gh_session, 'domain': 'github.com', 'path': '/'},
                                {'name': 'logged_in', 'value': 'yes', 'domain': 'github.com', 'path': '/'}
                            ])
                            self.log("已加载 Session Cookie", "SUCCESS")
                        except:
                            self.log("加载 Cookie 失败", "WARN")
                    
                    # ========== 步骤 1: 访问 ClawCloud 登录入口 ==========
                    self.log("步骤1: 打开 ClawCloud 登录页", "STEP")
                    page.goto(SIGNIN_URL, timeout=60000)
                    page.wait_for_load_state('networkidle', timeout=30000)
                    time.sleep(3)
                    self.shot(page, "01_clawcloud首页")
                    
                    current_url = page.url
                    self.log(f"当前 URL: {current_url}")
                    
                    # 检查是否已经登录（直接跳转到控制台）
                    if self.is_valid_console_page(current_url):
                        self.log("已登录，直接进入控制台！", "SUCCESS")
                        self.detect_region(current_url)
                        
                        # 验证登录状态
                        if self.keepalive(page):
                            new = self.get_session(context)
                            if new:
                                self.save_cookie(new)
                            self.notify(True)
                            print("\n✅ 成功！（已登录状态）\n")
                            return
                        else:
                            self.log("已登录但验证失败，尝试重新登录", "WARN")
                    
                    # ========== 步骤 2: 点击 GitHub 登录按钮 ==========
                    self.log("步骤2: 点击 GitHub 登录", "STEP")
                    
                    github_selectors = [
                        'button:has-text("GitHub")',
                        'a:has-text("GitHub")',
                        '[data-provider="github"]',
                        'button:has-text("Continue with GitHub")',
                        'a:has-text("Continue with GitHub")',
                        '.github-login',
                        '[class*="github"]'
                    ]
                    
                    if not self.click(page, github_selectors, "GitHub"):
                        self.log("找不到 GitHub 登录按钮", "ERROR")
                        self.shot(page, "找不到GitHub按钮")
                        self.notify(False, "找不到 GitHub 按钮")
                        sys.exit(1)
                    
                    time.sleep(3)
                    
                    # 等待页面加载
                    try:
                        page.wait_for_load_state('networkidle', timeout=30000)
                    except:
                        pass
                    
                    self.shot(page, "02_点击GitHub后")
                    
                    url = page.url
                    self.log(f"点击后 URL: {url}")
                    
                    # ========== 步骤 3: GitHub 认证 ==========
                    self.log("步骤3: GitHub 认证", "STEP")
                    
                    # 情况1: 需要登录 GitHub
                    if 'github.com/login' in url or 'github.com/session' in url:
                        self.log("需要登录 GitHub", "INFO")
                        if not self.login_github(page, context):
                            self.shot(page, "GitHub登录失败")
                            self.notify(False, "GitHub 登录失败")
                            sys.exit(1)
                        
                        # 登录后等待
                        time.sleep(3)
                        try:
                            page.wait_for_load_state('networkidle', timeout=30000)
                        except:
                            pass
                        
                        url = page.url
                        self.log(f"GitHub 登录后 URL: {url}")
                    
                    # 情况2: OAuth 授权页面
                    if 'github.com/login/oauth/authorize' in url:
                        self.log("Cookie 有效，处理 OAuth 授权", "SUCCESS")
                        self.oauth(page)
                        time.sleep(3)
                        try:
                            page.wait_for_load_state('networkidle', timeout=30000)
                        except:
                            pass
                    
                    self.shot(page, "03_GitHub认证后")
                    
                    # ========== 步骤 4: 等待重定向到控制台 ==========
                    self.log("步骤4: 等待重定向到控制台", "STEP")
                    
                    if not self.wait_redirect(page, wait=90):
                        self.shot(page, "重定向失败")
                        self.notify(False, "重定向到控制台失败")
                        sys.exit(1)
                    
                    self.shot(page, "04_重定向成功")
                    
                    # ========== 步骤 5: 验证登录状态 ==========
                    self.log("步骤5: 验证登录状态", "STEP")
                    
                    current_url = page.url
                    if not self.is_valid_console_page(current_url):
                        self.log(f"当前页面不是有效控制台: {current_url}", "ERROR")
                        self.shot(page, "非控制台页面")
                        self.notify(False, "未能进入控制台")
                        sys.exit(1)
                    
                    # 确保区域已检测
                    if not self.detected_region:
                        self.detect_region(current_url)
                    
                    # ========== 步骤 6: 保活验证 ==========
                    self.log("步骤6: 保活验证", "STEP")
                    
                    if not self.keepalive(page):
                        self.log("保活验证失败，登录可能未成功", "ERROR")
                        self.notify(False, "保活验证失败")
                        sys.exit(1)
                    
                    # ========== 步骤 7: 更新 Cookie ==========
                    self.log("步骤7: 更新 Cookie", "STEP")
                    
                    new = self.get_session(context)
                    if new:
                        self.save_cookie(new)
                    else:
                        self.log("未获取到新 Cookie（可能正常）", "WARN")
                    
                    # ========== 完成 ==========
                    self.notify(True)
                    
                    print("\n" + "="*50)
                    print("✅ 登录成功！")
                    if self.detected_region:
                        print(f"📍 区域: {self.detected_region}")
                    if self.region_base_url:
                        print(f"🌐 控制台: {self.region_base_url}")
                    if self.proxy.enabled:
                        print("🔒 代理: Hysteria2")
                    print("="*50 + "\n")
                    
                except Exception as e:
                    self.log(f"运行异常: {e}", "ERROR")
                    self.shot(page, "异常")
                    import traceback
                    traceback.print_exc()
                    self.notify(False, str(e))
                    sys.exit(1)
                    
                finally:
                    browser.close()
        
        finally:
            # 停止代理
            if self.proxy.enabled:
                self.proxy.stop()


# ==================== 主程序入口 ====================
if __name__ == "__main__":
    AutoLogin().run()
