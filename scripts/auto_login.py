"""
ClawCloud 自动登录脚本 (修复版)
- 支持 Hysteria2 代理
- 修复区域检测
- 添加 keepalive 验证
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
LOGIN_ENTRY_URL = "https://console.run.claw.cloud"
SIGNIN_URL = f"{LOGIN_ENTRY_URL}/signin"
DEVICE_VERIFY_WAIT = 30
TWO_FACTOR_WAIT = int(os.environ.get("TWO_FACTOR_WAIT", "120"))

# 代理配置
LOCAL_PROXY_PORT = 51080
LOCAL_HTTP_PORT = 51081


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
        if not self.hy2_url:
            return None
        
        try:
            url = self.hy2_url
            if url.startswith('hysteria2://'):
                url = url[12:]
            elif url.startswith('hy2://'):
                url = url[6:]
            
            if '#' in url:
                url, _ = url.rsplit('#', 1)
            
            params = {}
            if '?' in url:
                url, query = url.split('?', 1)
                params = parse_qs(query)
            
            if '@' in url:
                password, host_port = url.rsplit('@', 1)
                password = unquote(password)
            else:
                password = ''
                host_port = url
            
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
                'socks5': {'listen': f"127.0.0.1:{LOCAL_PROXY_PORT}"},
                'http': {'listen': f"127.0.0.1:{LOCAL_HTTP_PORT}"}
            }
            
            if 'alpn' in params:
                config['tls']['alpn'] = params['alpn'][0].split(',')
            
            print(f"  📍 服务器: {host}:{port}")
            print(f"  🔐 认证: {password[:4]}...{password[-4:] if len(password) > 8 else '***'}")
            print(f"  🌐 SNI: {config['tls']['sni']}")
            
            return config
            
        except Exception as e:
            print(f"❌ 解析 Hysteria2 URL 失败: {e}")
            return None
    
    def generate_config_json(self, config):
        json_file = '/tmp/hy2_config.json'
        with open(json_file, 'w') as f:
            json.dump(config, f, indent=2)
        return json_file
    
    def start(self):
        if not self.enabled:
            return True
        
        config = self.parse_url()
        if not config:
            return False
        
        try:
            import yaml
            with open(self.config_file, 'w') as f:
                yaml.dump(config, f)
            config_file = self.config_file
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
                print(f"❌ Hysteria2 启动失败: {stderr.decode()}")
                return False
            
            if self.test_proxy():
                print(f"✅ Hysteria2 代理已启动 (SOCKS5: 127.0.0.1:{LOCAL_PROXY_PORT})")
                return True
            
            self.stop()
            return False
                
        except FileNotFoundError:
            print("❌ 找不到 hysteria 命令")
            return False
        except Exception as e:
            print(f"❌ 启动失败: {e}")
            return False
    
    def test_proxy(self, retries=3):
        for i in range(retries):
            try:
                r = requests.get(
                    'https://api.ipify.org?format=json',
                    proxies={'http': f'socks5://127.0.0.1:{LOCAL_PROXY_PORT}',
                             'https': f'socks5://127.0.0.1:{LOCAL_PROXY_PORT}'},
                    timeout=10
                )
                if r.status_code == 200:
                    print(f"✅ 代理出口 IP: {r.json().get('ip')}")
                    return True
            except Exception as e:
                print(f"  测试 {i+1}/{retries}: {e}")
                time.sleep(2)
        return False
    
    def stop(self):
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.wait(timeout=5)
                print("✅ Hysteria2 已停止")
            except:
                try:
                    self.process.kill()
                except:
                    pass
    
    def get_playwright_proxy(self):
        if not self.enabled:
            return None
        return {'server': f'socks5://127.0.0.1:{LOCAL_PROXY_PORT}'}


class Telegram:
    def __init__(self, proxy=None):
        self.token = os.environ.get('TG_BOT_TOKEN')
        self.chat_id = os.environ.get('TG_CHAT_ID')
        self.ok = bool(self.token and self.chat_id)
        self.proxy = proxy
    
    def _proxies(self):
        if self.proxy and self.proxy.enabled:
            return {'http': f'socks5://127.0.0.1:{LOCAL_PROXY_PORT}',
                    'https': f'socks5://127.0.0.1:{LOCAL_PROXY_PORT}'}
        return None
    
    def send(self, msg):
        if not self.ok:
            return
        try:
            requests.post(
                f"https://api.telegram.org/bot{self.token}/sendMessage",
                data={"chat_id": self.chat_id, "text": msg, "parse_mode": "HTML"},
                timeout=30, proxies=self._proxies()
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
                    files={"photo": f}, timeout=60, proxies=self._proxies()
                )
        except:
            try:
                with open(path, 'rb') as f:
                    requests.post(
                        f"https://api.telegram.org/bot{self.token}/sendPhoto",
                        data={"chat_id": self.chat_id, "caption": caption[:1024]},
                        files={"photo": f}, timeout=60
                    )
            except:
                pass
    
    def flush_updates(self):
        if not self.ok:
            return 0
        try:
            r = requests.get(
                f"https://api.telegram.org/bot{self.token}/getUpdates",
                params={"timeout": 0}, timeout=10, proxies=self._proxies()
            )
            data = r.json()
            if data.get("ok") and data.get("result"):
                return data["result"][-1]["update_id"] + 1
        except:
            pass
        return 0
    
    def wait_code(self, timeout=120):
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
                    timeout=30, proxies=self._proxies()
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
            except:
                pass
            time.sleep(2)
        return None


class SecretUpdater:
    def __init__(self):
        self.token = os.environ.get('REPO_TOKEN')
        self.repo = os.environ.get('GITHUB_REPOSITORY')
        self.ok = bool(self.token and self.repo)
        print("✅ Secret 自动更新已启用" if self.ok else "⚠️ Secret 自动更新未启用")
    
    def update(self, name, value):
        if not self.ok:
            return False
        try:
            from nacl import encoding, public
            
            headers = {"Authorization": f"token {self.token}",
                       "Accept": "application/vnd.github.v3+json"}
            
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
                json={"encrypted_value": base64.b64encode(encrypted).decode(), 
                      "key_id": key_data['key_id']},
                timeout=30
            )
            return r.status_code in [201, 204]
        except Exception as e:
            print(f"更新 Secret 失败: {e}")
            return False


class AutoLogin:
    def __init__(self):
        self.username = os.environ.get('GH_USERNAME')
        self.password = os.environ.get('GH_PASSWORD')
        self.gh_session = os.environ.get('GH_SESSION', '').strip()
        
        self.proxy = Hysteria2Proxy()
        self.tg = Telegram(proxy=self.proxy)
        self.secret = SecretUpdater()
        self.shots = []
        self.logs = []
        self.n = 0
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
        """修复：支持 .run.claw.cloud 和 .console.claw.cloud"""
        try:
            parsed = urlparse(url)
            host = parsed.netloc
            
            # 支持两种格式
            for suffix in ['.run.claw.cloud', '.console.claw.cloud']:
                if host.endswith(suffix):
                    region = host.replace(suffix, '')
                    if region and region not in ['console', 'run']:
                        self.detected_region = region
                        self.region_base_url = f"https://{host}"
                        self.log(f"检测到区域: {region}", "SUCCESS")
                        return region
            
            # 从路径检测
            path = parsed.path
            region_match = re.search(r'/(?:region|r)/([a-z]+-[a-z]+-\d+)', path)
            if region_match:
                region = region_match.group(1)
                self.detected_region = region
                self.region_base_url = f"https://{region}.run.claw.cloud"
                return region
            
            self.log(f"使用当前域名: {host}", "INFO")
            self.region_base_url = f"{parsed.scheme}://{parsed.netloc}"
            return None
            
        except Exception as e:
            self.log(f"区域检测异常: {e}", "WARN")
            return None
    
    def get_base_url(self):
        return self.region_base_url or LOGIN_ENTRY_URL
    
    def get_session(self, context):
        try:
            for c in context.cookies():
                if c['name'] == 'user_session' and 'github' in c.get('domain', ''):
                    return c['value']
        except:
            pass
        return None
    
    def save_cookie(self, value):
        if not value:
            return
        self.log(f"新 Cookie: {value[:15]}...{value[-8:]}", "SUCCESS")
        if self.secret.update('GH_SESSION', value):
            self.log("已自动更新 GH_SESSION", "SUCCESS")
            self.tg.send("🔑 <b>Cookie 已自动更新</b>")
        else:
            self.tg.send(f"🔑 <b>新 Cookie</b>\n<code>{value}</code>")
    
    def is_logged_in(self, url):
        """检查是否已登录（不在登录页）"""
        url_lower = url.lower()
        return ('claw.cloud' in url_lower and 
                'signin' not in url_lower and 
                'callback' not in url_lower and
                'login' not in url_lower)
    
    def wait_device(self, page):
        self.log(f"需要设备验证，等待 {DEVICE_VERIFY_WAIT} 秒...", "WARN")
        self.shot(page, "设备验证")
        self.tg.send(f"⚠️ <b>需要设备验证</b>\n请在 {DEVICE_VERIFY_WAIT} 秒内批准")
        if self.shots:
            self.tg.photo(self.shots[-1], "设备验证页面")
        
        for i in range(DEVICE_VERIFY_WAIT):
            time.sleep(1)
            if i % 5 == 0:
                url = page.url
                if 'verified-device' not in url and 'device-verification' not in url:
                    self.log("设备验证通过！", "SUCCESS")
                    return True
                try:
                    page.reload(timeout=10000)
                    page.wait_for_load_state('networkidle', timeout=10000)
                except:
                    pass
        
        if 'verified-device' not in page.url:
            return True
        
        self.log("设备验证超时", "ERROR")
        return False
    
    def wait_two_factor_mobile(self, page):
        self.log(f"需要两步验证（GitHub Mobile），等待 {TWO_FACTOR_WAIT} 秒...", "WARN")
        shot = self.shot(page, "两步验证_mobile")
        self.tg.send(f"⚠️ <b>需要两步验证（GitHub Mobile）</b>\n等待时间：{TWO_FACTOR_WAIT} 秒")
        if shot:
            self.tg.photo(shot, "两步验证页面")
        
        for i in range(TWO_FACTOR_WAIT):
            time.sleep(1)
            url = page.url
            
            if "github.com/sessions/two-factor/" not in url:
                self.log("两步验证通过！", "SUCCESS")
                return True
            
            if "github.com/login" in url:
                self.log("两步验证后回到了登录页", "ERROR")
                return False
            
            if i % 10 == 0 and i != 0:
                self.log(f"  等待... ({i}/{TWO_FACTOR_WAIT}秒)")
        
        self.log("两步验证超时", "ERROR")
        return False
    
    def handle_2fa_code_input(self, page):
        self.log("需要输入验证码", "WARN")
        shot = self.shot(page, "两步验证_code")
        
        try:
            for sel in ['a:has-text("Use an authentication app")', '[href*="two-factor/app"]']:
                try:
                    el = page.locator(sel).first
                    if el.is_visible(timeout=2000):
                        el.click()
                        time.sleep(2)
                        page.wait_for_load_state('networkidle', timeout=15000)
                        shot = self.shot(page, "两步验证_切换后")
                        break
                except:
                    pass
        except:
            pass
        
        self.tg.send(f"🔐 <b>需要验证码</b>\n发送：<code>/code 你的6位验证码</code>\n等待：{TWO_FACTOR_WAIT} 秒")
        if shot:
            self.tg.photo(shot, "两步验证页面")
        
        code = self.tg.wait_code(timeout=TWO_FACTOR_WAIT)
        if not code:
            self.log("等待验证码超时", "ERROR")
            return False
        
        self.log("收到验证码，正在填入...", "SUCCESS")
        
        for sel in ['input[autocomplete="one-time-code"]', 'input[name="app_otp"]', 
                    'input[name="otp"]', 'input#app_totp']:
            try:
                el = page.locator(sel).first
                if el.is_visible(timeout=2000):
                    el.fill(code)
                    time.sleep(1)
                    
                    for btn in ['button:has-text("Verify")', 'button[type="submit"]']:
                        try:
                            b = page.locator(btn).first
                            if b.is_visible(timeout=1000):
                                b.click()
                                break
                        except:
                            pass
                    else:
                        page.keyboard.press("Enter")
                    
                    time.sleep(3)
                    page.wait_for_load_state('networkidle', timeout=30000)
                    
                    if "github.com/sessions/two-factor/" not in page.url:
                        self.log("验证码验证通过！", "SUCCESS")
                        return True
                    return False
            except:
                pass
        
        self.log("没找到验证码输入框", "ERROR")
        return False
    
    def login_github(self, page, context):
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
        
        if 'verified-device' in url or 'device-verification' in url:
            if not self.wait_device(page):
                return False
            time.sleep(2)
            page.wait_for_load_state('networkidle', timeout=30000)
        
        if 'two-factor' in page.url:
            self.log("需要两步验证！", "WARN")
            if 'two-factor/mobile' in page.url:
                if not self.wait_two_factor_mobile(page):
                    return False
            else:
                if not self.handle_2fa_code_input(page):
                    return False
            try:
                page.wait_for_load_state('networkidle', timeout=30000)
                time.sleep(2)
            except:
                pass
        
        try:
            err = page.locator('.flash-error').first
            if err.is_visible(timeout=2000):
                self.log(f"错误: {err.inner_text()}", "ERROR")
                return False
        except:
            pass
        
        return True
    
    def oauth(self, page):
        if 'github.com/login/oauth/authorize' in page.url:
            self.log("处理 OAuth...", "STEP")
            self.shot(page, "oauth")
            self.click(page, ['button[name="authorize"]', 'button:has-text("Authorize")'], "授权")
            time.sleep(3)
            page.wait_for_load_state('networkidle', timeout=30000)
    
    def wait_redirect(self, page, wait=60):
        self.log("等待重定向...", "STEP")
        for i in range(wait):
            url = page.url
            self.log(f"  [{i}s] URL: {url[:80]}...")
            
            # 检查是否成功登录到控制台
            if self.is_logged_in(url):
                self.log("重定向成功！", "SUCCESS")
                self.detect_region(url)
                return True
            
            # 处理 OAuth 授权页面
            if 'github.com/login/oauth/authorize' in url:
                self.oauth(page)
                continue
            
            # 处理 callback（需要等待处理完成）
            if 'callback' in url and 'claw.cloud' in url:
                self.log("正在处理 OAuth callback...", "INFO")
                time.sleep(3)
                page.wait_for_load_state('networkidle', timeout=30000)
                # 检查 callback 后的最终状态
                final_url = page.url
                if self.is_logged_in(final_url):
                    self.log("Callback 处理成功！", "SUCCESS")
                    self.detect_region(final_url)
                    return True
                elif 'signin' in final_url.lower():
                    self.log("Callback 后被重定向回登录页！", "ERROR")
                    self.shot(page, "callback失败")
                    return False
            
            time.sleep(1)
        
        self.log("重定向超时", "ERROR")
        return False
    
    def keepalive(self, page):
        """保活 - 验证是否真正登录成功"""
        self.log("保活验证...", "STEP")
        
        base_url = self.get_base_url()
        self.log(f"使用 URL: {base_url}", "INFO")
        
        login_success = False
        
        for url, name in [(f"{base_url}/", "控制台"), (f"{base_url}/apps", "应用")]:
            try:
                page.goto(url, timeout=30000)
                page.wait_for_load_state('networkidle', timeout=15000)
                time.sleep(2)
                
                current_url = page.url
                self.log(f"访问 {name}: {current_url[:60]}...", "INFO")
                
                # 检查是否被重定向回登录页
                if 'signin' in current_url.lower() or 'login' in current_url.lower():
                    self.log(f"❌ 访问 {name} 被重定向回登录页！", "ERROR")
                    self.shot(page, f"被踢回登录_{name}")
                    continue
                
                self.log(f"已访问: {name}", "SUCCESS")
                login_success = True
                self.detect_region(current_url)
                
            except Exception as e:
                self.log(f"访问 {name} 失败: {e}", "WARN")
        
        self.shot(page, "最终状态")
        
        # 返回是否真正登录成功
        return login_success
    
    def notify(self, ok, err=""):
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
        
        if self.shots:
            # 失败时发送最后3张，成功时发送最后1张
            to_send = self.shots[-3:] if not ok else self.shots[-1:]
            for s in to_send:
                self.tg.photo(s, s)
    
    def run(self):
        print("\n" + "="*50)
        print("🚀 ClawCloud 自动登录 (修复版)")
        print("="*50 + "\n")
        
        self.log(f"用户名: {self.username}")
        self.log(f"Session: {'有' if self.gh_session else '无'}")
        self.log(f"密码: {'有' if self.password else '无'}")
        self.log(f"代理: {'Hysteria2' if self.proxy.enabled else '无'}")
        
        if not self.username or not self.password:
            self.log("缺少凭据", "ERROR")
            self.notify(False, "凭据未配置")
            sys.exit(1)
        
        if self.proxy.enabled and not self.proxy.start():
            self.log("代理启动失败，继续直连...", "WARN")
            self.proxy.enabled = False
        
        try:
            with sync_playwright() as p:
                proxy_config = self.proxy.get_playwright_proxy()
                
                browser = p.chromium.launch(
                    headless=True,
                    args=['--no-sandbox', '--disable-blink-features=AutomationControlled']
                )
                
                context_opts = {
                    'viewport': {'width': 1920, 'height': 1080},
                    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                if proxy_config:
                    context_opts['proxy'] = proxy_config
                    self.log(f"Playwright 代理: {proxy_config['server']}", "INFO")
                
                context = browser.new_context(**context_opts)
                page = context.new_page()
                
                try:
                    if self.gh_session:
                        context.add_cookies([
                            {'name': 'user_session', 'value': self.gh_session, 
                             'domain': 'github.com', 'path': '/'},
                            {'name': 'logged_in', 'value': 'yes', 
                             'domain': 'github.com', 'path': '/'}
                        ])
                        self.log("已加载 Session Cookie", "SUCCESS")
                    
                    # 1. 访问登录页
                    self.log("步骤1: 打开登录页", "STEP")
                    page.goto(SIGNIN_URL, timeout=60000)
                    page.wait_for_load_state('networkidle', timeout=30000)
                    time.sleep(2)
                    self.shot(page, "登录页")
                    
                    current_url = page.url
                    self.log(f"当前 URL: {current_url}")
                    
                    if self.is_logged_in(current_url):
                        self.log("已登录！", "SUCCESS")
                        self.detect_region(current_url)
                        if self.keepalive(page):
                            new = self.get_session(context)
                            if new:
                                self.save_cookie(new)
                            self.notify(True)
                            print("\n✅ 成功！\n")
                            return
                        else:
                            self.notify(False, "Session 已失效")
                            sys.exit(1)
                    
                    # 2. 点击 GitHub
                    self.log("步骤2: 点击 GitHub", "STEP")
                    if not self.click(page, [
                        'button:has-text("GitHub")',
                        'a:has-text("GitHub")',
                        '[data-provider="github"]'
                    ], "GitHub"):
                        self.log("找不到按钮", "ERROR")
                        self.notify(False, "找不到 GitHub 按钮")
                        sys.exit(1)
                    
                    time.sleep(3)
                    page.wait_for_load_state('networkidle', timeout=30000)
                    self.shot(page, "点击后")
                    
                    url = page.url
                    self.log(f"当前: {url}")
                    
                    # 3. GitHub 登录
                    self.log("步骤3: GitHub 认证", "STEP")
                    
                    if 'github.com/login' in url or 'github.com/session' in url:
                        if not self.login_github(page, context):
                            self.shot(page, "登录失败")
                            self.notify(False, "GitHub 登录失败")
                            sys.exit(1)
                    elif 'github.com/login/oauth/authorize' in url:
                        self.log("Cookie 有效", "SUCCESS")
                        self.oauth(page)
                    
                    # 4. 等待重定向
                    self.log("步骤4: 等待重定向", "STEP")
                    if not self.wait_redirect(page):
                        self.shot(page, "重定向失败")
                        self.notify(False, "重定向失败")
                        sys.exit(1)
                    
                    self.shot(page, "重定向成功")
                    
                    # 5. 保活验证
                    self.log("步骤5: 保活验证", "STEP")
                    if not self.keepalive(page):
                        self.notify(False, "登录验证失败，被重定向回登录页")
                        sys.exit(1)
                    
                    # 6. 更新 Cookie
                    self.log("步骤6: 更新 Cookie", "STEP")
                    new = self.get_session(context)
                    if new:
                        self.save_cookie(new)
                    else:
                        self.log("未获取到新 Cookie", "WARN")
                    
                    self.notify(True)
                    print("\n✅ 成功！\n")
                    
                except Exception as e:
                    self.log(f"异常: {e}", "ERROR")
                    self.shot(page, "异常")
                    import traceback
                    traceback.print_exc()
                    self.notify(False, str(e))
                    sys.exit(1)
                finally:
                    browser.close()
        
        finally:
            self.proxy.stop()


if __name__ == "__main__":
    AutoLogin().run()
