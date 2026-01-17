"""
ClawCloud 自动登录脚本
- 自动检测区域跳转
- 正确处理 OAuth callback
- 等待设备验证批准
- Telegram 通知
"""

import os
import sys
import time
import base64
import re
import requests
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

# ==================== 配置 ====================
LOGIN_ENTRY_URL = "https://console.run.claw.cloud"
SIGNIN_URL = f"{LOGIN_ENTRY_URL}/signin"
DEVICE_VERIFY_WAIT = 30
TWO_FACTOR_WAIT = int(os.environ.get("TWO_FACTOR_WAIT", "120"))

REGION_PATTERNS = [
    r'([a-z]+-[a-z]+-\d+)\.run\.claw\.cloud',
    r'([a-z]+-[a-z]+-\d+)\.console\.claw\.cloud',
]


class Telegram:
    def __init__(self):
        self.token = os.environ.get('TG_BOT_TOKEN')
        self.chat_id = os.environ.get('TG_CHAT_ID')
        self.ok = bool(self.token and self.chat_id)
    
    def send(self, msg):
        if not self.ok:
            return
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
                    timeout=60
                )
        except:
            pass
    
    def flush_updates(self):
        if not self.ok:
            return 0
        try:
            r = requests.get(
                f"https://api.telegram.org/bot{self.token}/getUpdates",
                params={"timeout": 0},
                timeout=10
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
                    timeout=30
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
        if self.ok:
            print("✅ Secret 自动更新已启用")
        else:
            print("⚠️ Secret 自动更新未启用")
    
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
    def __init__(self):
        self.username = os.environ.get('GH_USERNAME')
        self.password = os.environ.get('GH_PASSWORD')
        self.gh_session = os.environ.get('GH_SESSION', '').strip()
        self.tg = Telegram()
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
    
    def is_logged_in(self, url):
        """
        判断是否真正登录成功
        排除: signin, callback, login, github.com
        """
        if 'github.com' in url:
            return False
        if 'claw.cloud' not in url:
            return False
        
        # 这些路径表示未登录或登录中
        not_logged_patterns = ['/signin', '/callback', '/login', '/auth']
        path = urlparse(url).path.lower()
        
        for pattern in not_logged_patterns:
            if pattern in path:
                return False
        
        # 如果在 claw.cloud 且不在上述路径，认为登录成功
        return True
    
    def detect_region(self, url):
        try:
            parsed = urlparse(url)
            host = parsed.netloc
            
            for pattern in REGION_PATTERNS:
                match = re.search(pattern, host)
                if match:
                    region = match.group(1)
                    self.detected_region = region
                    if '.run.claw.cloud' in host:
                        self.region_base_url = f"https://{region}.run.claw.cloud"
                    else:
                        self.region_base_url = f"https://{region}.console.claw.cloud"
                    self.log(f"检测到区域: {region}", "SUCCESS")
                    return region
            
            if 'claw.cloud' in host:
                self.region_base_url = f"https://{host}"
            return None
            
        except Exception as e:
            self.log(f"区域检测异常: {e}", "WARN")
            return None
    
    def get_base_url(self):
        if self.region_base_url:
            return self.region_base_url
        return LOGIN_ENTRY_URL
    
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
        return False
    
    def wait_two_factor_mobile(self, page):
        self.log(f"需要两步验证（GitHub Mobile），等待 {TWO_FACTOR_WAIT} 秒...", "WARN")
        
        shot = self.shot(page, "两步验证_mobile")
        self.tg.send(f"⚠️ <b>需要 GitHub Mobile 验证</b>\n等待: {TWO_FACTOR_WAIT} 秒")
        if shot:
            self.tg.photo(shot, "两步验证页面")
        
        for i in range(TWO_FACTOR_WAIT):
            time.sleep(1)
            url = page.url
            
            if "github.com/sessions/two-factor/" not in url:
                self.log("两步验证通过！", "SUCCESS")
                return True
            
            if "github.com/login" in url and "two-factor" not in url:
                self.log("被踢回登录页", "ERROR")
                return False
            
            if i % 10 == 0 and i != 0:
                self.log(f"  等待... ({i}/{TWO_FACTOR_WAIT}秒)")
            
            if i % 30 == 0 and i != 0:
                try:
                    page.reload(timeout=30000)
                    page.wait_for_load_state('domcontentloaded', timeout=30000)
                except:
                    pass
        
        self.log("两步验证超时", "ERROR")
        return False
    
    def handle_2fa_code_input(self, page):
        self.log("需要输入验证码", "WARN")
        shot = self.shot(page, "两步验证_code")
        
        # 尝试切换到 TOTP 输入
        try:
            for sel in ['a:has-text("Use an authentication app")', 'a:has-text("Enter a code")']:
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
        
        self.tg.send(f"🔐 <b>请发送验证码</b>\n<code>/code 123456</code>\n等待: {TWO_FACTOR_WAIT}秒")
        if shot:
            self.tg.photo(shot, "两步验证页面")
        
        code = self.tg.wait_code(timeout=TWO_FACTOR_WAIT)
        
        if not code:
            self.log("等待验证码超时", "ERROR")
            return False
        
        self.log("收到验证码，正在填入...", "SUCCESS")
        
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
                    time.sleep(1)
                    
                    # 提交
                    for btn_sel in ['button:has-text("Verify")', 'button[type="submit"]']:
                        try:
                            btn = page.locator(btn_sel).first
                            if btn.is_visible(timeout=1000):
                                btn.click()
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
                    else:
                        self.log("验证码可能错误", "ERROR")
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
        
        # 设备验证
        if 'verified-device' in url or 'device-verification' in url:
            if not self.wait_device(page):
                return False
            time.sleep(2)
            page.wait_for_load_state('networkidle', timeout=30000)
        
        # 2FA
        if 'two-factor' in page.url:
            self.log("需要两步验证！", "WARN")
            self.shot(page, "两步验证")
            
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
        
        # 检查错误
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
            self.log("处理 OAuth 授权...", "STEP")
            self.shot(page, "oauth")
            self.click(page, ['button[name="authorize"]', 'button:has-text("Authorize")'], "授权")
            time.sleep(3)
            page.wait_for_load_state('networkidle', timeout=30000)
    
    def wait_for_login_complete(self, page, timeout=60):
        """
        等待真正登录成功
        需要等待 callback 处理完成，跳转到控制台
        """
        self.log("等待登录完成...", "STEP")
        
        for i in range(timeout):
            try:
                # 等待网络空闲
                page.wait_for_load_state('networkidle', timeout=5000)
            except:
                pass
            
            url = page.url
            
            # 每10秒打印状态
            if i % 10 == 0:
                self.log(f"  当前 URL: {url[:80]}...")
            
            # 检查是否真正登录成功
            if self.is_logged_in(url):
                self.log(f"登录成功！URL: {url}", "SUCCESS")
                self.detect_region(url)
                return True
            
            # 如果在 callback 页面，等待它处理
            if '/callback' in url:
                self.log("  处理 OAuth callback...", "INFO") if i % 5 == 0 else None
                time.sleep(1)
                continue
            
            # 如果在 OAuth 授权页面
            if 'github.com/login/oauth/authorize' in url:
                self.oauth(page)
                continue
            
            # 如果被踢回 signin 页面（登录失败）
            if '/signin' in url and 'callback' not in url:
                # 检查是否刚进入，等几秒看看会不会继续跳转
                if i < 10:
                    time.sleep(1)
                    continue
                self.log("被重定向到登录页，登录可能失败", "WARN")
                self.shot(page, "回到登录页")
                # 继续等待，可能只是临时状态
            
            # 如果还在 GitHub 登录流程
            if 'github.com' in url:
                if 'login' in url and 'oauth' not in url:
                    self.log("需要 GitHub 登录", "WARN")
                    return False
            
            time.sleep(1)
        
        self.log(f"等待超时，最终 URL: {page.url}", "ERROR")
        return False
    
    def verify_login(self, page):
        """
        验证是否真正登录成功
        尝试访问需要登录的页面，检查是否被重定向到 signin
        """
        self.log("验证登录状态...", "STEP")
        
        base_url = self.get_base_url()
        test_url = f"{base_url}/apps"  # 需要登录才能访问的页面
        
        try:
            page.goto(test_url, timeout=30000, wait_until='domcontentloaded')
            time.sleep(3)
            
            try:
                page.wait_for_load_state('networkidle', timeout=15000)
            except:
                pass
            
            current_url = page.url
            self.log(f"验证 URL: {current_url}")
            
            # 如果被重定向到 signin，说明没登录成功
            if '/signin' in current_url:
                self.log("登录验证失败：被重定向到登录页", "ERROR")
                self.shot(page, "验证失败_signin")
                return False
            
            # 如果还在 callback 或 github
            if '/callback' in current_url or 'github.com' in current_url:
                self.log("登录验证失败：仍在认证流程中", "ERROR")
                self.shot(page, "验证失败_callback")
                return False
            
            # 检查页面内容，确认是控制台
            try:
                # 查找一些控制台特有的元素
                indicators = [
                    'text=Apps',
                    'text=Application',
                    'text=Create',
                    '[class*="app"]',
                    '[class*="dashboard"]'
                ]
                for ind in indicators:
                    try:
                        if page.locator(ind).first.is_visible(timeout=2000):
                            self.log("找到控制台元素，登录确认成功！", "SUCCESS")
                            return True
                    except:
                        pass
            except:
                pass
            
            # 如果 URL 正常且没被重定向，认为成功
            if self.is_logged_in(current_url):
                self.log("URL 检查通过，登录成功！", "SUCCESS")
                return True
            
            self.log(f"无法确认登录状态: {current_url}", "WARN")
            return False
            
        except Exception as e:
            self.log(f"验证登录异常: {e}", "ERROR")
            return False
    
    def keepalive(self, page):
        """保活操作"""
        self.log("执行保活...", "STEP")
        
        base_url = self.get_base_url()
        self.log(f"使用 URL: {base_url}")
        
        pages_to_visit = [
            (f"{base_url}/apps", "应用列表"),
            (f"{base_url}/", "控制台首页"),
        ]
        
        for url, name in pages_to_visit:
            try:
                self.log(f"访问: {name}")
                page.goto(url, timeout=30000, wait_until='domcontentloaded')
                time.sleep(3)
                
                try:
                    page.wait_for_load_state('networkidle', timeout=15000)
                except:
                    pass
                
                current_url = page.url
                
                # 检查是否被踢到登录页
                if '/signin' in current_url:
                    self.log(f"访问 {name} 被重定向到登录页！", "ERROR")
                    return False
                
                self.log(f"已访问: {name}", "SUCCESS")
                
            except Exception as e:
                self.log(f"访问 {name} 失败: {e}", "WARN")
        
        self.shot(page, "保活完成")
        return True
    
    def notify(self, ok, err=""):
        if not self.tg.ok:
            return
        
        region_info = f"\n<b>区域:</b> {self.detected_region}" if self.detected_region else ""
        
        msg = f"""<b>🤖 ClawCloud 自动登录</b>

<b>状态:</b> {"✅ 成功" if ok else "❌ 失败"}
<b>用户:</b> {self.username}{region_info}
<b>时间:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}"""
        
        if err:
            msg += f"\n<b>错误:</b> {err}"
        
        msg += "\n\n<b>日志:</b>\n" + "\n".join(self.logs[-10:])
        
        self.tg.send(msg)
        
        if self.shots:
            if not ok:
                for s in self.shots[-3:]:
                    self.tg.photo(s, s)
            else:
                self.tg.photo(self.shots[-1], "完成")
    
    def run(self):
        print("\n" + "="*50)
        print("🚀 ClawCloud 自动登录")
        print("="*50 + "\n")
        
        self.log(f"用户名: {self.username}")
        self.log(f"Session: {'有' if self.gh_session else '无'}")
        self.log(f"密码: {'有' if self.password else '无'}")
        
        if not self.username or not self.password:
            self.log("缺少凭据", "ERROR")
            self.notify(False, "凭据未配置")
            sys.exit(1)
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=['--no-sandbox'])
            context = browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            )
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
                
                # 1. 访问登录页
                self.log("步骤1: 打开登录页", "STEP")
                page.goto(SIGNIN_URL, timeout=60000, wait_until='domcontentloaded')
                time.sleep(3)
                
                try:
                    page.wait_for_load_state('networkidle', timeout=30000)
                except:
                    pass
                
                self.shot(page, "登录页")
                current_url = page.url
                self.log(f"当前: {current_url}")
                self.detect_region(current_url)
                
                # 检查是否已登录
                if self.is_logged_in(current_url):
                    self.log("已登录！", "SUCCESS")
                    if self.verify_login(page):
                        if self.keepalive(page):
                            new = self.get_session(context)
                            if new:
                                self.save_cookie(new)
                            self.notify(True)
                            print("\n✅ 成功！\n")
                            return
                    else:
                        self.log("登录状态验证失败", "WARN")
                
                # 2. 点击 GitHub 登录
                self.log("步骤2: 点击 GitHub 登录", "STEP")
                if not self.click(page, [
                    'button:has-text("GitHub")',
                    'a:has-text("GitHub")',
                    '[data-provider="github"]',
                    'button:has-text("Continue with GitHub")',
                    'a:has-text("Continue with GitHub")',
                    'button:has-text("Sign in with GitHub")',
                ], "GitHub"):
                    self.log("找不到 GitHub 按钮", "ERROR")
                    self.shot(page, "找不到按钮")
                    self.notify(False, "找不到 GitHub 按钮")
                    sys.exit(1)
                
                time.sleep(3)
                try:
                    page.wait_for_load_state('networkidle', timeout=30000)
                except:
                    pass
                
                self.shot(page, "点击后")
                url = page.url
                self.log(f"当前: {url}")
                
                # 3. GitHub 认证
                self.log("步骤3: GitHub 认证", "STEP")
                
                if 'github.com/login' in url and 'oauth' not in url:
                    if not self.login_github(page, context):
                        self.shot(page, "GitHub登录失败")
                        self.notify(False, "GitHub 登录失败")
                        sys.exit(1)
                    
                    # 登录后再次检查
                    time.sleep(2)
                    url = page.url
                    self.log(f"GitHub 登录后: {url}")
                    
                if 'github.com/login/oauth/authorize' in url:
                    self.log("处理 OAuth 授权", "SUCCESS")
                    self.oauth(page)
                
                # 4. 等待登录完成（关键修复！）
                self.log("步骤4: 等待登录完成", "STEP")
                if not self.wait_for_login_complete(page, timeout=60):
                    self.shot(page, "登录未完成")
                    
                    # 再尝试检查当前状态
                    url = page.url
                    self.log(f"当前状态: {url}")
                    
                    if '/signin' in url:
                        self.notify(False, "登录后被重定向回登录页，可能被检测为机器人")
                    elif '/callback' in url:
                        self.notify(False, "OAuth callback 处理超时")
                    else:
                        self.notify(False, f"登录未完成: {url}")
                    sys.exit(1)
                
                self.shot(page, "登录完成")
                
                # 5. 验证登录状态
                self.log("步骤5: 验证登录", "STEP")
                if not self.verify_login(page):
                    self.shot(page, "验证失败")
                    self.notify(False, "登录验证失败")
                    sys.exit(1)
                
                # 6. 保活
                self.log("步骤6: 保活", "STEP")
                if not self.keepalive(page):
                    self.notify(False, "保活失败，登录状态可能无效")
                    sys.exit(1)
                
                # 7. 保存 Cookie
                self.log("步骤7: 保存 Cookie", "STEP")
                new = self.get_session(context)
                if new:
                    self.save_cookie(new)
                else:
                    self.log("未获取到新 Cookie", "WARN")
                
                self.notify(True)
                print("\n" + "="*50)
                print("✅ 成功！")
                if self.detected_region:
                    print(f"📍 区域: {self.detected_region}")
                print("="*50 + "\n")
                
            except Exception as e:
                self.log(f"异常: {e}", "ERROR")
                self.shot(page, "异常")
                import traceback
                traceback.print_exc()
                self.notify(False, str(e))
                sys.exit(1)
            finally:
                browser.close()


if __name__ == "__main__":
    AutoLogin().run()
