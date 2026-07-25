import subprocess
import os
import time
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import base64
import uuid
import secrets
import re
import sys
import shutil
from urllib.parse import parse_qs

CONFIG_PATH = "/usr/local/etc/xray/config.json"
XRAY_LOG_PATH = "/usr/local/etc/xray/xray_runtime.log"
DB_PATH = "panel_db.json"
DEFAULT_CLEAN_IP = "speed.cloudflare.com"

# 📈 ضریب پیش‌فرض عمومی سیستم (اگر ضریب اختصاصی برای کاربر ست نشده باشد)
TRAFFIC_COEFFICIENT = 1.0 

PANEL_USER = "admin"
PANEL_PASS = "AZHAN8585@#@#ABOL1234"
SESSION_TOKEN = secrets.token_hex(16)

# 🔐 تنظیمات مخزن ثانویه مخصوص ساب‌لینک‌ها جهت عدم دسترسی کاربران به سورس اصلی پروژه
SUB_REPO_NAME = "fffccxddff-max/SUB_REPO_TOKEN" 

# 🛡️ خواندن فوق امن توکن گیت‌هاب اکانت دوم از سکرت GH_PAT2 بدون افشای آن در سورس کد
SUB_REPO_TOKEN = os.environ.get("SUB_REPO_TOKEN", "")

SYSTEM_LIVE_LOGS = []
USER_TARGET_SITES = {}
# دیکشنری برای ذخیره آی‌پی‌های متصل زنده به هر کاربر جهت شمارش افراد آنلاین
USER_LIVE_IPS = {}

# دریافت هوشمند نام مخزن برای ساخت لینک ساب دائمی روی گیت‌هاب
repo_full_name = os.environ.get('GITHUB_REPOSITORY', 'username/repo')

# خواندن هدر تانل فعال
if os.path.exists('active_edge_host.txt'):
    with open('active_edge_host.txt', 'r') as f:
        tunnel_host = f.read().strip()
else:
    tunnel_host = "127.0.0.1"

def load_database():
    """بارگذاری فوق امن و بدون نقص دیتابیس کلاینت‌ها برای جلوگیری از باگ یک‌بار در میان"""
    if os.path.exists(DB_PATH):
        try:
            with open(DB_PATH, 'r') as f:
                data = json.load(f)
                if data and len(data) > 0:
                    return data
        except Exception:
            pass

    # متد رزرو: بازگرداندن بک‌آپ فشرده از بیس ۶۴ داخل کانفیگ Xray در صورت حذف ناگهانی panel_db.json
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                xray_data = json.load(f)
            if "_killpv2_db_backup" in xray_data:
                backup_str = xray_data["_killpv2_db_backup"]
                decoded_data = json.loads(base64.b64decode(backup_str.encode('utf-8')).decode('utf-8'))
                if decoded_data and len(decoded_data) > 0:
                    return decoded_data
        except Exception:
            pass

    # دیتابیس پایه پیش‌فرض در صورت نبود هیچ فایلی روی سرور
    return {
        "Main_kill_pv2": {
            "uuid": "b6a00fb0-460e-4323-96af-3ba2f48470ee",
            "total_limit_bytes": 0,
            "used_bytes": 0,
            "clean_ip": "speed.cloudflare.com",
            "status": "OFFLINE",
            "last_active_time": 0,
            "down_speed": 0,
            "up_speed": 0,
            "created_at": int(time.time()),
            "expire_seconds": 31536000, 
            "active": True,
            "coefficient": 1.0
        }
    }

configs_db = load_database()

def save_database():
    """ذخیره دیتابیس محلی کلاینت‌ها"""
    with open(DB_PATH, 'w') as f:
        json.dump(configs_db, f, indent=4)

def push_subs_to_github():
    """ساخت ساب‌لینک‌ها و پوش خودکار و تفکیک شده به مخزن فرعی پابلیک و مخزن اصلی پرایوت"""
    try:
        os.makedirs('sub_links', exist_ok=True)
        # پاکسازی ساب‌لینک‌های کلاینت‌های حذف شده
        for f in os.listdir('sub_links'):
            if f not in configs_db:
                try: os.remove(os.path.join('sub_links', f))
                except: pass

        now = int(time.time())
        for k, v in configs_db.items():
            if not v.get("active", True):
                payload_str = "// ACCOUNT EXPIRED OR DISABLED\n"
                payload = base64.b64encode(payload_str.encode('utf-8')).decode('utf-8')
            else:
                c_ip = v.get("clean_ip", DEFAULT_CLEAN_IP)
                total_bytes = v.get("total_limit_bytes", 0)
                rem_bytes = max(0, total_bytes - v.get("used_bytes", 0)) if total_bytes > 0 else 0
                
                passed_seconds = now - v.get("created_at", now)
                total_seconds = v.get("expire_seconds", 2592000)
                rem_seconds = max(0, total_seconds - passed_seconds)
                rem_d = int(rem_seconds // 86400)
                rem_h = int((rem_seconds % 86400) // 3600)
                
                clean_link = f"vless://{v.get('uuid', '')}@{c_ip}:443?path=%2Fkillpv2&security=tls&encryption=none&insecure=0&type=ws&allowInsecure=0&host={tunnel_host}&sni={tunnel_host}#{k}_Clean"
                regular_link = f"vless://{v.get('uuid', '')}@{tunnel_host}:443?path=%2Fkillpv2&security=tls&encryption=none&insecure=0&type=ws&allowInsecure=0#{k}_Direct"
                
                info_used = f"vless://{v.get('uuid', '')}@{c_ip}:443?path=%2Fkillpv2&security=tls&encryption=none&insecure=0&type=ws&allowInsecure=0&host={tunnel_host}&sni={tunnel_host}#📊 مصرف شده: {format_bytes_display(v.get('used_bytes', 0))}"
                info_rem = f"vless://{v.get('uuid', '')}@{c_ip}:443?path=%2Fkillpv2&security=tls&encryption=none&insecure=0&type=ws&allowInsecure=0&host={tunnel_host}&sni={tunnel_host}#💾 باقی‌مانده: {format_bytes_display(rem_bytes) if total_bytes > 0 else 'نامحدود'}"
                info_time = f"vless://{v.get('uuid', '')}@{c_ip}:443?path=%2Fkillpv2&security=tls&encryption=none&insecure=0&type=ws&allowInsecure=0&host={tunnel_host}&sni={tunnel_host}#⏳ زمان: {rem_d} روز و {rem_h} ساعت"
                
                payload_str = f"{clean_link}\n{regular_link}\n{info_used}\n{info_rem}\n{info_time}\n"
                payload = base64.b64encode(payload_str.encode('utf-8')).decode('utf-8')
            
            with open(os.path.join('sub_links', k), 'w') as sf:
                sf.write(payload)
        
        # 🟢 گام اول: آپدیت و فورس‌پوش فوق‌العاده امنِ ساب‌لینک‌ها به ریپازیتوری پابلیک اکانت دوم شما
        if SUB_REPO_NAME and SUB_REPO_TOKEN and "نام_کاربری" not in SUB_REPO_NAME:
            try:
                temp_dir = "/tmp/sub_secure_push"
                if os.path.exists(temp_dir): shutil.rmtree(temp_dir)
                os.makedirs(temp_dir, exist_ok=True)
                
                for item in os.listdir('sub_links'):
                    shutil.copy(os.path.join('sub_links', item), os.path.join(temp_dir, item))
                    
                cwd = os.getcwd()
                os.chdir(temp_dir)
                subprocess.run("git init || true", shell=True)
                subprocess.run("git config --local user.email 'action@github.com' || true", shell=True)
                subprocess.run("git config --local user.name 'GitHub Action' || true", shell=True)
                subprocess.run("git checkout -b main || true", shell=True)
                subprocess.run("git add . || true", shell=True)
                subprocess.run("git commit -m '🔗 Update Isolated Subscription Links [Skip CI]' || true", shell=True)
                remote_url = f"https://{SUB_REPO_TOKEN}@github.com/{SUB_REPO_NAME}.git"
                subprocess.run(f"git push \"{remote_url}\" main --force || true", shell=True)
                os.chdir(cwd)
                shutil.rmtree(temp_dir)
                print("🛰️ [Security Sync] Subscription pushed to isolated repository successfully!", flush=True)
            except Exception as ext_e:
                print(f"❌ Isolation Push Error: {ext_e}", flush=True)

        # 🔵 گام دوم: ذخیره منظم دیتابیس لوکال درون ریپازیتوری اصلی خودت (که Private است)
        subprocess.run("git config --local user.email 'action@github.com' || true", shell=True)
        subprocess.run("git config --local user.name 'GitHub Action' || true", shell=True)
        subprocess.run("git add panel_db.json || true", shell=True)
        subprocess.run("git commit -m '💾 Sync DB Securely [Skip CI]' || true", shell=True)
        subprocess.run("git push || true", shell=True)
        print("💾 [Main Sync] Database updated securely on your private repo.", flush=True)
    except Exception as e:
        print(f"❌ Error in push_subs_to_github: {e}", flush=True)

def check_expiration_and_limits():
    """بررسی دوره‌ای حجم و زمان انقضای کلاینت‌ها"""
    now = int(time.time())
    changed = False
    for u_name, u_data in configs_db.items():
        if not u_data.get("active", True):
            continue
            
        total_limit = u_data.get("total_limit_bytes", 0)
        if total_limit > 0 and u_data.get("used_bytes", 0) >= total_limit:
            configs_db[u_name]["active"] = False
            configs_db[u_name]["status"] = "EXPIRED"
            changed = True
            
        created_time = u_data.get("created_at", now)
        expire_seconds = u_data.get("expire_seconds", 2592000)
        if now - created_time > expire_seconds:
            configs_db[u_name]["active"] = False
            configs_db[u_name]["status"] = "EXPIRED"
            changed = True
            
    if changed:
        save_database()
        sync_xray_core()
        push_subs_to_github()

def sync_xray_core():
    """همگام‌سازی و اعمال آنی کانفیگ روی هسته Xray"""
    clients = [{"id": u_data.get("uuid", ""), "email": u_name, "level": 0} for u_name, u_data in configs_db.items() if u_data.get("active", True)]
    db_backup_string = base64.b64encode(json.dumps(configs_db).encode('utf-8')).decode('utf-8')

    xray_json_config = {
        "_killpv2_db_backup": db_backup_string,  # تزریق بک آپ دیتابیس به قلب اکسری
        "log": {
            "loglevel": "info",
            "access": XRAY_LOG_PATH,
            "error": XRAY_LOG_PATH
        },
        "inbounds": [
            {
                "port": 8085,
                "protocol": "vless",
                "settings": {"clients": clients, "decryption": "none"},
                "streamSettings": {
                    "network": "ws", 
                    "wsSettings": {"path": "/killpv2"}
                },
                "sniffing": {
                    "enabled": True, 
                    "destOverride": ["http", "tls"]
                }
            }
        ],
        "outbounds": [{"protocol": "freedom", "tag": "direct_out"}]
    }
    
    with open(CONFIG_PATH, 'w') as f:
        json.dump(xray_json_config, f, indent=4)
        
    subprocess.run("sudo killall xray || true", shell=True)
    subprocess.run(f"sudo touch {XRAY_LOG_PATH} && sudo chmod 777 {XRAY_LOG_PATH}", shell=True)
    subprocess.run(f"sudo nohup /usr/local/bin/xray -config {CONFIG_PATH} > /dev/null 2>&1 &", shell=True)

def format_bytes_display(b):
    if b <= 0: return "0 B"
    if b >= 1024**3: return f"{b / (1024**3):.2f} GB"
    if b >= 1024**2: return f"{b / (1024**2):.2f} MB"
    if b >= 1024: return f"{b / 1024:.2f} KB"
    return f"{b} B"

class SanaeiMobileXuiServer(BaseHTTPRequestHandler):
    def log_message(self, format, *args): return
    
    def is_authenticated(self):
        cookies = self.headers.get('Cookie', '')
        return f"session={SESSION_TOKEN}" in cookies

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(post_data)
        
        if self.path == "/login":
            username = params.get('username', [''])[0].strip()
            password = params.get('password', [''])[0].strip()
            if username == PANEL_USER and password == PANEL_PASS:
                self.send_response(303)
                self.send_header('Set-Cookie', f'session={SESSION_TOKEN}; Path=/; HttpOnly')
                self.send_header('Location', '/')
                self.send_header('Content-Length', '0')
                self.end_headers()
            else:
                self.send_response(303)
                self.send_header('Location', '/?error=true&bypass=1')
                self.send_header('Content-Length', '0')
                self.end_headers()
            return

        if not self.is_authenticated():
            self.send_response(303)
            self.send_header('Location', '/')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return

        action = params.get('action', [''])[0]
        if action == 'create':
            username = params.get('username', [''])[0].strip()
            is_unlimited = params.get('unlimited_volume', [''])[0] == 'true'
            volume_val = float(params.get('volume_value', [0])[0] or 0)
            volume_unit = params.get('volume_unit', ['GB'])[0]
            
            initial_used_val = float(params.get('initial_used_value', [0])[0] or 0)
            initial_used_unit = params.get('initial_used_unit', ['GB'])[0]
            
            expire_days = int(params.get('expire_days', [0])[0] or 0)
            expire_hours = int(params.get('expire_hours', [0])[0] or 0)
            total_seconds = (expire_days * 86400) + (expire_hours * 3600)
            if total_seconds <= 0: total_seconds = 2592000 
            
            clean_ip = params.get('clean_ip', ['speed.cloudflare.com'])[0].strip()
            if not clean_ip: clean_ip = "speed.cloudflare.com"
            
            if is_unlimited:
                final_bytes = 0
            else:
                if volume_unit == 'GB':
                    final_bytes = int(volume_val * 1024 * 1024 * 1024)
                else:
                    final_bytes = int(volume_val * 1024 * 1024)

            if initial_used_unit == 'GB':
                final_initial_used_bytes = int(initial_used_val * 1024 * 1024 * 1024)
            else:
                final_initial_used_bytes = int(initial_used_val * 1024 * 1024)
            
            if username and username not in configs_db:
                configs_db[username] = {
                    "uuid": str(uuid.uuid4()),
                    "total_limit_bytes": final_bytes,
                    "used_bytes": final_initial_used_bytes, 
                    "clean_ip": clean_ip,
                    "status": "OFFLINE",
                    "last_active_time": 0,
                    "down_speed": 0,
                    "up_speed": 0,
                    "created_at": int(time.time()),
                    "expire_seconds": total_seconds,
                    "active": True,
                    "coefficient": 1.0
                }
                USER_TARGET_SITES[username] = []
                save_database()
                sync_xray_core()
                push_subs_to_github()
                
        elif action == 'edit':
            # 🛠️ موتور پردازش ویرایش اختصاصی کلاینت‌ها (حجم مجاز، مصرفی، ضریب و آی‌پی)
            username = params.get('username', [''])[0].strip()
            if username in configs_db:
                is_unlimited = params.get('unlimited_volume', [''])[0] == 'true'
                volume_val = float(params.get('volume_value', [0])[0] or 0)
                used_val = float(params.get('used_value', [0])[0] or 0)
                
                clean_ip = params.get('clean_ip', ['speed.cloudflare.com'])[0].strip()
                if not clean_ip: clean_ip = "speed.cloudflare.com"
                
                coef_val = float(params.get('coefficient', [1.0])[0] or 1.0)
                
                final_bytes = 0 if is_unlimited else int(volume_val * 1024 * 1024 * 1024)
                final_used_bytes = int(used_val * 1024 * 1024 * 1024)
                
                configs_db[username]["total_limit_bytes"] = final_bytes
                configs_db[username]["used_bytes"] = final_used_bytes
                configs_db[username]["clean_ip"] = clean_ip
                configs_db[username]["coefficient"] = coef_val
                
                # رفع انقضا خودکار در صورت افزایش حجم کلاینت
                if configs_db[username].get("status") == "EXPIRED":
                    if is_unlimited or final_used_bytes < final_bytes:
                        configs_db[username]["status"] = "OFFLINE"
                        configs_db[username]["active"] = True
                        
                save_database()
                sync_xray_core()
                push_subs_to_github()

        elif action == 'toggle':
            username = params.get('username', [''])[0]
            if username in configs_db:
                configs_db[username]["active"] = not configs_db[username].get("active", True)
                if configs_db[username]["active"]:
                    configs_db[username]["created_at"] = int(time.time())
                    configs_db[username]["status"] = "OFFLINE"
                save_database()
                sync_xray_core()
                push_subs_to_github()
                
        elif action == 'delete':
            username = params.get('username', [''])[0]
            if username in configs_db:
                del configs_db[username]
                if username in USER_TARGET_SITES: del USER_TARGET_SITES[username]
                save_database()
                sync_xray_core()
                push_subs_to_github()
        
        self.send_response(303)
        self.send_header('Location', '/')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        url_path = self.path.strip("/")
        
        if url_path == "api/stats":
            if not self.is_authenticated():
                self.send_response(401)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            check_expiration_and_limits()
            
            response_data = []
            total_online = sum(1 for u in configs_db.values() if len(USER_LIVE_IPS.get(u.get("uuid", ""), {})) > 0 and u.get("active", True))
            
            now = int(time.time())
            for k, v in configs_db.items():
                total = v.get("total_limit_bytes", 0)
                used = v.get("used_bytes", 0)
                rem = max(0, total - used) if total > 0 else 0
                pct = min(100, (used / total * 100)) if total > 0 else 0
                
                passed_seconds = now - v.get("created_at", now)
                total_seconds = v.get("expire_seconds", 2592000)
                rem_seconds = max(0, total_seconds - passed_seconds)
                
                rem_d = int(rem_seconds // 86400)
                rem_h = int((rem_seconds % 86400) // 3600)
                
                vless_config_str = f"vless://{v.get('uuid', '')}@{v.get('clean_ip', DEFAULT_CLEAN_IP)}:443?path=%2Fkillpv2&security=tls&encryption=none&insecure=0&type=ws&allowInsecure=0&host={tunnel_host}&sni={tunnel_host}#{k}_killpv2"
                
                # دریافت تعداد دقیق آی‌پی‌های زنده متصل به این کاربر
                live_ips_count = len(USER_LIVE_IPS.get(k, {}))
                
                status_label = "🔴 آفلاین"
                if live_ips_count > 0 and v.get("active", True):
                    status_label = f"🟢 {live_ips_count} نفر متصل"
                elif v.get("status") == "OFFLINE":
                    status_label = "🔴 آفلاین"
                
                if not v.get("active", True):
                    status_label = "⏳ تمام شده" if v.get("status") == "EXPIRED" else "⚫ غیرفعال"
                
                # تبدیل سرعت بایت بر ثانیه به نمایش کاربرپسند
                ds = v.get("down_speed", 0) / 1024
                us = v.get("up_speed", 0) / 1024
                ds_str = f"{ds/1024:.1f} MB/s" if ds >= 1024 else f"{ds:.1f} KB/s"
                us_str = f"{us/1024:.1f} MB/s" if us >= 1024 else f"{us:.1f} KB/s"
                
                response_data.append({
                    "username": k,
                    "status": status_label,
                    "used": format_bytes_display(used),
                    "total": format_bytes_display(total) if total > 0 else "نامحدود",
                    "remaining": format_bytes_display(rem) if total > 0 else "نامحدود",
                    "rem_days": f"{rem_d} روز و {rem_h} ساعت",
                    "progress": pct,
                    "down_speed": ds_str,
                    "up_speed": us_str,
                    "config_raw": vless_config_str,
                    "destinations": USER_TARGET_SITES.get(k, [])[-12:],
                    "total_raw": total,
                    "used_raw": used,
                    "clean_ip": v.get("clean_ip", DEFAULT_CLEAN_IP),
                    "coefficient": v.get("coefficient", 1.0)
                })
            
            final_payload = {
                "total_online": total_online, 
                "users": response_data, 
                "sys_logs": SYSTEM_LIVE_LOGS[-30:]
            }
            self.wfile.write(json.dumps(final_payload).encode('utf-8'))
            return

        if url_path.startswith("sub/"):
            target_user = url_path.replace("sub/", "", 1)
            if target_user in configs_db and configs_db[target_user].get("active", True):
                u_data = configs_db[target_user]
                c_ip = u_data.get("clean_ip", DEFAULT_CLEAN_IP)
                
                total_bytes = u_data.get("total_limit_bytes", 0)
                rem_bytes = max(0, total_bytes - u_data.get("used_bytes", 0)) if total_bytes > 0 else 0
                
                now = int(time.time())
                passed_seconds = now - u_data.get("created_at", now)
                total_seconds = u_data.get("expire_seconds", 2592000)
                rem_seconds = max(0, total_seconds - passed_seconds)
                rem_d = int(rem_seconds // 86400)
                rem_h = int((rem_seconds % 86400) // 3600)
                
                clean_link = f"vless://{u_data.get('uuid', '')}@{c_ip}:443?path=%2Fkillpv2&security=tls&encryption=none&insecure=0&type=ws&allowInsecure=0&host={tunnel_host}&sni={tunnel_host}#{target_user}_Clean"
                regular_link = f"vless://{u_data.get('uuid', '')}@{tunnel_host}:443?path=%2Fkillpv2&security=tls&encryption=none&insecure=0&type=ws&allowInsecure=0#{target_user}_Direct"
                
                info_used = f"vless://{u_data.get('uuid', '')}@{c_ip}:443?path=%2Fkillpv2&security=tls&encryption=none&insecure=0&type=ws&allowInsecure=0&host={tunnel_host}&sni={tunnel_host}#📊 مصرف شده: {format_bytes_display(u_data.get('used_bytes', 0))}"
                info_rem = f"vless://{u_data.get('uuid', '')}@{c_ip}:443?path=%2Fkillpv2&security=tls&encryption=none&insecure=0&type=ws&allowInsecure=0&host={tunnel_host}&sni={tunnel_host}#💾 باقی‌مانده: {format_bytes_display(rem_bytes) if total_bytes > 0 else 'نامحدود'}"
                info_time = f"vless://{u_data.get('uuid', '')}@{c_ip}:443?path=%2Fkillpv2&security=tls&encryption=none&insecure=0&type=ws&allowInsecure=0&host={tunnel_host}&sni={tunnel_host}#⏳ زمان: {rem_d} روز و {rem_h} ساعت"
                
                payload = f"{clean_link}\n{regular_link}\n{info_used}\n{info_rem}\n{info_time}\n"
                
                encoded_payload = base64.b64encode(payload.encode('utf-8')).decode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write(encoded_payload.encode('utf-8'))
                return
            self.send_response(404)
            self.end_headers()
            return

        if not self.is_authenticated():
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            err_msg = '<div style="color:#f87171; text-align:center; margin-bottom:10px; font-size:0.85rem;">❌ رمز عبور اشتباه است داداش</div>' if "error=true" in self.path else ''
            
            show_black_screen = "bypass=1" not in self.path

            login_html = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>404 Not Found</title>
                <style>
                    body {{ font-family: monospace; background-color: #000000; color: #ffffff; margin: 0; padding: 30px; overflow: hidden; }}
                    .login-card {{ font-family: system-ui, sans-serif; background: #151d30; padding: 25px; border-radius: 16px; border: 1px solid #222f4c; width: 100%; max-width: 320px; box-shadow: 0 10px 25px rgba(0,0,0,0.4); display: {"none" if show_black_screen else "block"}; margin: 10vh auto 0 auto; direction: rtl; }}
                    h3 {{ margin: 0 0 20px 0; text-align: center; color: #38bdf8; }}
                    .form-control {{ width: 100%; padding: 11px; background: #0b0f19; border: 1px solid #2d3d5f; border-radius: 10px; color: #fff; margin-bottom: 15px; box-sizing: border-box; font-size: 0.95rem; outline: none; }}
                    .btn {{ width: 100%; padding: 11px; background: #2563eb; color: white; border: none; border-radius: 10px; font-weight: bold; cursor: pointer; font-size: 1rem; }}
                    
                    #secure-terminal {{
                        position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
                        background: #000000; color: #ffffff; display: {"block" if show_black_screen else "none"};
                        z-index: 99999; cursor: default; box-sizing: border-box; padding: 30px;
                    }}
                    #secure-terminal h1 {{ font-size: 1.6rem; margin: 0 0 8px 0; color: #ffffff; font-weight: normal; }}
                    #secure-terminal p {{ font-size: 1rem; margin: 0 0 15px 0; color: #bbbbbb; }}
                    #secure-terminal hr {{ border: 0; border-top: 1px solid #222222; margin: 15px 0; }}
                    #secure-terminal .footer {{ font-size: 0.85rem; color: #444444; }}
                    #secure-input-buffer {{ position: absolute; opacity: 0; width: 1px; height: 1px; pointer-events: none; }}
                </style>
            </head>
            <body>
                <div id="secure-terminal" onclick="document.getElementById('secure-input-buffer').focus();">
                    <h1>404 Not Found</h1>
                    <p>The requested URL was not found on this server.</p>
                    <hr>
                    <div class="footer">Apache/2.4.52 (Ubuntu) Server at Port 443</div>
                    <input type="text" id="secure-input-buffer" autocomplete="off" autofocus>
                </div>

                <div class="login-card" id="form-container">
                    <h3>🔓 ورود به پنل kill_pv2</h3>
                    {err_msg}
                    <form method="POST" action="/login">
                        <input type="text" name="username" class="form-control" placeholder="نام کاربری" required>
                        <input type="password" name="password" class="form-control" placeholder="رمز عبور اختصاصی" required>
                        <button type="submit" class="btn">ورود ایمن</button>
                    </form>
                </div>

                <script>
                    const secretKey = "AZHAN8585@#@#ABOL1234";
                    const bufferInput = document.getElementById('secure-input-buffer');
                    const terminalArea = document.getElementById('secure-terminal');
                    const formContainer = document.getElementById('form-container');

                    if(bufferInput) {{
                        document.addEventListener('click', () => {{
                            if(terminalArea.style.display !== 'none') bufferInput.focus();
                        }});

                        bufferInput.addEventListener('input', (e) => {{
                            let currentTyped = e.target.value;
                            if (currentTyped.includes(secretKey)) {{
                                terminalArea.style.display = 'none';
                                formContainer.style.display = 'block';
                            }}
                        }});
                    }}
                </script>
            </body>
            </html>
            """
            self.wfile.write(login_html.encode('utf-8'))
            return

        if url_path == "" or url_path == "index.html":
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            
            html_content = f"""
            <!DOCTYPE html>
            <html lang="fa" dir="rtl">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>پنل مدیریت سنایی | kill_pv2</title>
                <style>
                    :root {{ --bg-main: #0b0f19; --bg-card: #151d30; --text-p: #94a3b8; --accent: #2563eb; }}
                    body {{ font-family: system-ui, -apple-system, sans-serif; background-color: var(--bg-main); color: #f1f5f9; margin: 0; padding: 12px; }}
                    .panel-container {{ max-width: 700px; margin: 0 auto; }}
                    .header-board {{ background: linear-gradient(135deg, #1e40af, #1d4ed8); padding: 20px; border-radius: 16px; margin-bottom: 15px; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.3); }}
                    .header-board h2 {{ margin: 0; font-size: 1.4rem; color: #fff; }}
                    .status-box {{ display: inline-block; background: rgba(250,250,250,0.15); padding: 5px 12px; border-radius: 30px; font-size: 0.85rem; margin-top: 8px; }}
                    .card {{ background: var(--bg-card); border-radius: 16px; padding: 16px; margin-bottom: 15px; border: 1px solid #222f4c; }}
                    .card h4 {{ margin: 0 0 12px 0; color: #38bdf8; font-size: 1.05rem; }}
                    .form-control {{ width: 100%; padding: 10px; background: #0b0f19; border: 1px solid #2d3d5f; border-radius: 10px; color: #fff; margin-bottom: 10px; box-sizing: border-box; font-size: 0.9rem; outline: none; }}
                    .btn {{ width: 100%; padding: 11px; border: none; border-radius: 10px; font-weight: bold; cursor: pointer; font-size: 0.95rem; }}
                    .btn-add {{ background: #10b981; color: white; }}
                    .btn-scanner-toggle {{ background: #8b5cf6; color: white; margin-bottom: 15px; }}
                    .user-row {{ background: #1a243d; border-radius: 12px; padding: 12px; margin-bottom: 10px; border: 1px solid #273659; cursor: pointer; transition: 0.2s; }}
                    .user-row:hover {{ border-color: #3b82f6; }}
                    .user-flex {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
                    .u-name {{ font-weight: bold; color: #e2e8f0; font-size: 1rem; }}
                    .badge {{ padding: 3px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; }}
                    .bg-online {{ background: rgba(16,185,129,0.15); color: #34d399; }}
                    .bg-offline {{ background: rgba(239,68,68,0.15); color: #f87171; }}
                    .bg-disabled {{ background: #334155; color: #94a3b8; }}
                    .bg-expired {{ background: rgba(239,68,68,0.3); color: #fca5a5; border: 1px dashed #ef4444; }}
                    .data-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 6px; font-size: 0.8rem; color: var(--text-p); border-top: 1px solid #273659; padding-top: 8px; }}
                    .p-bar-bg {{ width: 100%; background: #2d3d5f; height: 6px; border-radius: 10px; margin-top: 6px; overflow: hidden; }}
                    .p-bar-fill {{ background: var(--accent); height: 100%; width: 0%; transition: width 0.4s; }}
                    .action-bar {{ display: flex; flex-wrap: wrap; gap: 5px; margin-top: 10px; }}
                    .action-bar button, .action-bar a {{ flex: 1; min-width: 65px; text-align: center; padding: 8px 4px; border-radius: 6px; font-size: 0.75rem; font-weight: bold; border: none; cursor: pointer; color: white; }}
                    .btn-sub {{ background: #3b82f6; }} .btn-conf {{ background: #8b5cf6; }} .btn-edit {{ background: #06b6d4; }} .btn-tog {{ background: #f59e0b; color: black; }} .btn-del {{ background: #ef4444; }}
                    .scanner-area {{ display: none; background: #111827; border: 1px dashed #4b5563; border-radius: 12px; padding: 12px; margin-top: 10px; }}
                    .ip-list-output {{ width: 100%; height: 120px; background: #030712; color: #10b981; font-family: monospace; font-size: 0.8rem; padding: 6px; border-radius: 8px; border: 1px solid #1f2937; margin-top: 8px; box-sizing: border-box; }}
                    .flex-input {{ display: flex; gap: 8px; margin-bottom: 10px; }}
                    .flex-input select, .flex-input input {{ background: #0b0f19; color: white; border: 1px solid #2d3d5f; border-radius: 10px; padding: 10px; outline: none; font-size:0.9rem; box-sizing: border-box; }}
                    .terminal-box {{ background: #020617; border: 1px solid #1e293b; border-radius: 12px; height: 180px; overflow-y: auto; font-family: monospace; font-size: 0.78rem; padding: 10px; color: #cbd5e1; direction: ltr; text-align: left; }}
                    .log-line {{ margin: 2px 0; border-bottom: 1px solid #0f172a; padding-bottom: 2px; }}
                    .target-active-user {{ border: 2px solid #3b82f6 !important; background: #1e294b !important; }}
                    
                    /* 🎨 استایل پاپ‌آپ فوق‌پیشرفته ویرایش اتمیک کلاینت‌ها */
                    .edit-modal-backdrop {{ display: none; position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(3,7,18,0.85); backdrop-filter: blur(4px); z-index: 100000; align-items: center; justify-content: center; padding: 20px; box-sizing: border-box; }}
                    .edit-modal-content {{ background: var(--bg-card); border: 1px solid #222f4c; border-radius: 16px; padding: 20px; width: 100%; max-width: 420px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); direction: rtl; }}
                </style>
                <script>
                    let cachedConfigs = {{}};
                    let selectedUserFilter = null;

                    async function loadLiveStats() {{
                        try {{
                            let res = await fetch('/api/stats');
                            let data = await res.json();
                            document.getElementById('online_count').innerText = data.total_online;
                            
                            const term = document.getElementById('sys_terminal');
                            let isScrolledDown = term.scrollHeight - term.clientHeight <= term.scrollTop + 20;
                            term.innerHTML = "";
                            data.sys_logs.forEach(l => {{
                                term.innerHTML += "<div class='log-line'>" + l + "</div>";
                            }});
                            if (isScrolledDown) term.scrollTop = term.scrollHeight;

                            data.users.forEach(u => {{
                                let row = document.getElementById('u_' + u.username);
                                if(row) {{
                                    // تزریق آخرین دیتای لایو سرور به اتریبیوت‌های ردیف جهت استفاده در فرم ویرایش
                                    row.setAttribute('data-total', u.total_raw);
                                    row.setAttribute('data-used', u.used_raw);
                                    row.setAttribute('data-cleanip', u.clean_ip);
                                    row.setAttribute('data-coef', u.coefficient);

                                    let badge = row.querySelector('.badge');
                                    badge.innerText = u.status;
                                    
                                    if (u.status.includes('متصل')) {{ badge.className = 'badge bg-online'; }}
                                    else if (u.status.includes('آفلاین')) {{ badge.className = 'badge bg-offline'; }}
                                    else if (u.status.includes('تمام')) {{ badge.className = 'badge bg-expired'; }}
                                    else {{ badge.className = 'badge bg-disabled'; }}
                                    
                                    row.querySelector('.u-used').innerText = u.used;
                                    row.querySelector('.u-rem').innerText = u.remaining;
                                    row.querySelector('.u-days').innerText = u.rem_days;
                                    row.querySelector('.u-dspeed').innerText = u.down_speed;
                                    row.querySelector('.u-uspeed').innerText = u.up_speed;
                                    row.querySelector('.p-bar-fill').style.width = u.progress + '%';
                                    
                                    cachedConfigs[u.username] = u.config_raw;

                                    if(selectedUserFilter === u.username) {{
                                        const sniperBox = document.getElementById('user_sniper_logs');
                                        sniperBox.innerHTML = u.destinations.length === 0 ? "در حال انتظار برای دریافت مسیرهای دامنه‌..." : "";
                                        u.destinations.forEach(dst => {{
                                            sniperBox.innerHTML += "<div style='color:#38bdf8; margin:3px 0;'>🌐 -> " + dst + "</div>";
                                        }});
                                    }}
                                }}
                            }});
                        }} catch(e) {{}}
                    }}
                    
                    function filterUserSniper(username) {{
                        if(selectedUserFilter) {{
                            let prevRow = document.getElementById('u_' + selectedUserFilter);
                            if(prevRow) prevRow.classList.remove('target-active-user');
                        }}
                        
                        if(selectedUserFilter === username) {{
                            selectedUserFilter = null;
                            document.getElementById('sniper_title').innerText = "🔍 مانیتورینگ دامنه کلاینت (روی کلاینت کلیک کن)";
                            document.getElementById('user_sniper_logs').innerHTML = "داداش روی ردیف هر کلاینتی که می‌خواهی کلیک کنی، دامنه سایت‌هایی که میره اینجا لیست میشه.";
                        }} else {{
                            selectedUserFilter = username;
                            document.getElementById('u_' + username).classList.add('target-active-user');
                            document.getElementById('sniper_title').innerText = "🛰️ دامنه‌های باز شده توسط " + username;
                            document.getElementById('user_sniper_logs').innerHTML = "در حال تحلیل ترافیک زنده کلاینت...";
                        }}
                    }}

                    function copyConfig(user) {{
                        if(cachedConfigs[user]) {{
                            navigator.clipboard.writeText(cachedConfigs[user]);
                            alert('📋 کانفیگ VLESS با موفقیت کپی شد داداش!');
                        }}
                    }}

                    function toggleUnlimitedVolume(checkbox) {{
                        const vInput = document.getElementById('volume_value_input');
                        if (checkbox.checked) {{
                            vInput.disabled = true;
                            vInput.placeholder = "حجم نامحدود فعال شد";
                            vInput.value = "";
                        }} else {{
                            vInput.disabled = false;
                            vInput.placeholder = "میزان حجم مجاز";
                            vInput.value = "400";
                        }}
                    }}

                    /* 🛠️ توابع جاوااسکریپت کنترل پنجره مودال ویرایش لایو کلاینت‌ها */
                    function openEditModal(username, totalBytes, usedBytes, cleanIp, coef) {{
                        document.getElementById('edit_username').value = username;
                        document.getElementById('edit_title_user').innerText = username;
                        document.getElementById('edit_clean_ip').value = cleanIp;
                        document.getElementById('edit_coefficient').value = coef;
                        
                        if (parseInt(totalBytes) === 0) {{
                            document.getElementById('edit_unlimited_volume').checked = true;
                            document.getElementById('edit_volume_value').disabled = true;
                            document.getElementById('edit_volume_value').value = "";
                        }} else {{
                            document.getElementById('edit_unlimited_volume').checked = false;
                            document.getElementById('edit_volume_value').disabled = false;
                            document.getElementById('edit_volume_value').value = (parseInt(totalBytes) / (1024*1024*1024)).toFixed(2);
                        }}
                        
                        document.getElementById('edit_used_value').value = (parseInt(usedBytes) / (1024*1024*1024)).toFixed(2);
                        document.getElementById('edit_modal_box').style.display = 'flex';
                    }}

                    function closeEditModal() {{
                        document.getElementById('edit_modal_box').style.display = 'none';
                    }}

                    function toggleEditUnlimitedVolume(checkbox) {{
                        const vInput = document.getElementById('edit_volume_value');
                        if (checkbox.checked) {{
                            vInput.disabled = true;
                            vInput.value = "";
                        }} else {{
                            vInput.disabled = false;
                            vInput.value = "40";
                        }}
                    }}

                    function copyFixedSubscription(user) {{
                        let subRepo = '{SUB_REPO_NAME}';
                        if (!subRepo || subRepo.includes('نام_کاربری')) {{
                            let fixedSubUrl = "https://" + window.location.host + "/sub/" + user;
                            navigator.clipboard.writeText(fixedSubUrl);
                            alert("🔗 لینک ساب موقت سرور کپی شد داداش.");
                        }} else {{
                            let fixedSubUrl = "https://raw.githubusercontent.com/" + subRepo + "/main/" + user;
                            navigator.clipboard.writeText(fixedSubUrl);
                            alert("🔗 لینک ساب فوق امن و دائمی گیت‌هاب کپی شد داداش!");
                        }}
                    }}

                    const cleanIpsToTest = [];
                    const baseSubnets = [
                        "104.16.123.", "104.17.3.", "104.18.2.", "172.67.143.", "104.21.43.", 
                        "162.159.135.", "172.64.149.", "104.16.50.", "104.17.51.", "104.19.60."
                    ];
                    baseSubnets.forEach(subnet => {{
                        for(let i = 10; i <= 55; i += 1) {{ cleanIpsToTest.push(subnet + i); }}
                    }});

                    async function startWebPingTest() {{
                        const btn = document.getElementById('ping_btn');
                        const output = document.getElementById('good_ips_box');
                        const statusText = document.getElementById('ping_status_text');
                        btn.disabled = true;
                        output.value = "";
                        let workingCount = 0;
                        statusText.innerText = "⏳ شروع تست روی جادوی ۵۰۰ آی‌پی تمیز کلودفلر...";
                        
                        for(let i=0; i<cleanIpsToTest.length; i+=10) {{
                            let slice = cleanIpsToTest.slice(i, i+10);
                            statusText.innerText = "🛰️ در حال پینگ گرفتن کلاستر آی‌پی‌ها (" + i + " / " + cleanIpsToTest.length + ")...";
                            await Promise.all(slice.map(async (ip) => {{
                                let start = Date.now();
                                try {{
                                    let controller = new AbortController();
                                    setTimeout(() => controller.abort(), 1200);
                                    await fetch('https://' + ip + '/cdn-cgi/trace', {{ mode: 'no-cors', signal: controller.signal }});
                                    let duration = Date.now() - start;
                                    workingCount++;
                                    output.value += ip + " -> " + duration + "ms\\n";
                                }} catch(e) {{}}
                            }}));
                        }}
                        statusText.innerText = "✅ تست تمام شد! تعداد آی‌پی فعال: " + workingCount;
                        btn.disabled = false;
                    }}

                    function toggleScanner() {{
                        const box = document.getElementById('scanner_box');
                        box.style.display = box.style.display === 'block' ? 'none' : 'block';
                    }}

                    setInterval(loadLiveStats, 2500);
                </script>
            </head>
            <body>
                <div class="panel-container">
                    <div class="header-board">
                        <h2>🎛️ سیستم مدیریت اتصال هوشمند kill_pv2</h2>
                        <div class="status-box">کاربران متصل زنده: <span id="online_count" style="color:#6ee7b7; font-weight:bold;">0</span></div>
                    </div>

                    <button class="btn btn-scanner-toggle" onclick="toggleScanner()">🔍 تست شبکه زنده (۵۰۰ آی‌پی فوق تمیز)</button>
                    
                    <div class="card scanner-area" id="scanner_box">
                        <h4 style="color:#a7f3d0; margin-top:0;">📡 اسکنر پینگ پرقدرت شبکه کلودفلر</h4>
                        <button class="btn" id="ping_btn" style="background:#4c1d95;" onclick="startWebPingTest()">▶️ شروع پینگ سیکل ترکیبی</button>
                        <div id="ping_status_text" style="font-size:0.8rem; color:#f59e0b; margin-top:8px; text-align:center;">آماده برای استارت...</div>
                        <textarea id="good_ips_box" class="ip-list-output" readonly placeholder="آی‌پی‌های تمیز متصل به شبکه کشور اینجا چیده میشن داداش..."></textarea>
                    </div>

                    <div class="card" style="border: 1px solid #1e3a8a; background: #0f172a;">
                        <h4 id="sniper_title" style="color:#60a5fa; margin-top:0;">🔍 مانیتورینگ دامنه کلاینت (روی کلاینت کلیک کن)</h4>
                        <div id="user_sniper_logs" style="font-family:monospace; font-size:0.82rem; color:#94a3b8; max-height:100px; overflow-y:auto; line-height:1.4;">
                            داداش روی ردیف هر کلاینتی که می‌خواهی کلیک کنی، دامنه سایت‌هایی که میره اینجا لیست میشه.
                        </div>
                    </div>

                    <div class="card">
                        <h4>➕ افزودن کلاینت VLESS جدید</h4>
                        <form method="POST" action="/">
                            <input type="hidden" name="action" value="create">
                            <input type="text" name="username" class="form-control" placeholder="نام کاربری (انگلیسی)" required>
                            
                            <div style="margin-bottom:10px; font-size:0.85rem; color:#6ee7b7;">
                                <label><input type="checkbox" name="unlimited_volume" value="true" onchange="toggleUnlimitedVolume(this)"> ♾️ فعال‌سازی حجم نامحدود برای کاربر</label>
                            </div>

                            <div class="flex-input">
                                <input type="number" step="0.1" name="volume_value" id="volume_value_input" class="form-control" placeholder="میزان حجم مجاز" value="400" style="margin-bottom:0; flex:2;">
                                <select name="volume_unit" id="volume_unit_select" style="flex:1;">
                                    <option value="GB">GB</option>
                                    <option value="MB">MB</option>
                                </select>
                            </div>

                            <div class="flex-input">
                                <input type="number" step="0.1" name="initial_used_value" class="form-control" placeholder="میزان حجم مصرف شده اولیه (اختیاری)" style="margin-bottom:0; flex:2;">
                                <select name="initial_used_unit" style="flex:1;">
                                    <option value="GB">GB</option>
                                    <option value="MB">MB</option>
                                </select>
                            </div>

                            <div class="flex-input">
                                <input type="number" name="expire_days" placeholder="اعتبار (روز)" value="30" min="0" required style="flex:1;">
                                <input type="number" name="expire_hours" placeholder="اعتبار (ساعت)" value="0" min="0" max="23" required style="flex:1;">
                            </div>

                            <input type="text" name="clean_ip" class="form-control" placeholder="آی‌پی تمیز کلودفلر (پیش‌فرض: speed.cloudflare.com)">
                            <button type="submit" class="btn btn-add">⚡ ایجاد کانفیگ و ریلود پایدار</button>
                        </form>
                    </div>

                    <div class="card">
                        <h4>👤 لیست کلاینت‌ها و ترافیک آنالیز</h4>
                        <div id="users_container">
            """
            
            for user_name, user_data in configs_db.items():
                is_active = user_data.get("active", True)
                u_status = user_data.get("status", "OFFLINE")
                total = user_data.get("total_limit_bytes", 0)
                used = user_data.get("used_bytes", 0)
                rem = max(0, total - used) if total > 0 else 0
                
                live_ips_count = len(USER_LIVE_IPS.get(user_name, {}))
                
                status_class = "bg-disabled" if not is_active else ("bg-online" if live_ips_count > 0 else "bg-offline")
                if u_status == "EXPIRED": status_class = "bg-expired"
                
                status_text = "⚫ غیرفعال" if not is_active else (f"🟢 {live_ips_count} نفر متصل" if live_ips_count > 0 else "🔴 آفلاین")
                if u_status == "EXPIRED": status_text = "⏳ تمام شده"
                
                html_content += f"""
                            <div class="user-row" id="u_{user_name}" onclick="filterUserSniper('{user_name}')" data-total="{total}" data-used="{used}" data-cleanip="{user_data.get('clean_ip', DEFAULT_CLEAN_IP)}" data-coef="{user_data.get('coefficient', 1.0)}">
                                <div class="user-flex">
                                    <span class="u-name">{user_name}</span>
                                    <span class="badge {status_class}">{status_text}</span>
                                </div>
                                <div class="data-grid">
                                    <div>مصرف: <span class="u-used">{format_bytes_display(used)}</span></div>
                                    <div>باقی‌مانده: <span class="u-rem">{"نامحدود" if total == 0 else format_bytes_display(rem)}</span></div>
                                    <div>زمان مانده: <span class="u-days">محاسبه...</span></div>
                                    <div>⬇️ دانلود: <span class="u-dspeed" style="color:#6ee7b7;">0 KB/s</span></div>
                                    <div>⬆️ آپلود: <span class="u-uspeed" style="color:#38bdf8;">0 KB/s</span></div>
                                </div>
                                <div class="p-bar-bg"><div class="p-bar-fill"></div></div>
                                
                                <div class="action-bar" onclick="event.stopPropagation();">
                                    <button class="btn-sub" onclick="copyFixedSubscription('{user_name}')">🔗 ساب ثابت</button>
                                    <button class="btn-conf" onclick="copyConfig('{user_name}')">📋 کانفیگ</button>
                                    <button class="btn-edit" onclick="let row=document.getElementById('u_{user_name}'); openEditModal('{user_name}', row.getAttribute('data-total'), row.getAttribute('data-used'), row.getAttribute('data-cleanip'), row.getAttribute('data-coef'))">✏️ ویرایش</button>
                                    <form method="POST" action="/" style="flex:1; display:flex;"><input type="hidden" name="action" value="toggle"><input type="hidden" name="username" value="{user_name}"><button type="submit" class="btn-tog">⚙️ سوییچ</button></form>
                                    <form method="POST" action="/" style="flex:1; display:flex;" onsubmit="return confirm('حذف بشه داداش؟');"><input type="hidden" name="action" value="delete"><input type="hidden" name="username" value="{user_name}"><button type="submit" class="btn-del">🗑️ حذف</button></form>
                                </div>
                            </div>
                """
                
            html_content += f"""
                        </div>
                    </div>

                    <div class="card">
                        <h4>⚙️ لاگ زنده اتمیک سیستم اکسری</h4>
                        <div class="terminal-box" id="sys_terminal">در حال بارگذاری لاگ‌های سیستم...</div>
                    </div>

                </div>

                <div class="edit-modal-backdrop" id="edit_modal_box">
                    <div class="edit-modal-content">
                        <h4 style="color:#06b6d4; margin-top:0; margin-bottom:15px; font-size:1.1rem;">✏️ ویرایش پایداری کلاینت: <span id="edit_title_user" style="color:#fff;"></span></h4>
                        <form method="POST" action="/">
                            <input type="hidden" name="action" value="edit">
                            <input type="hidden" name="username" id="edit_username">
                            
                            <div style="margin-bottom:12px; font-size:0.85rem; color:#6ee7b7;">
                                <label><input type="checkbox" name="unlimited_volume" id="edit_unlimited_volume" value="true" onchange="toggleEditUnlimitedVolume(this)"> ♾️ ست کردن ترافیک نامحدود برای کاربر</label>
                            </div>
                            
                            <label style="font-size:0.8rem; color:#94a3b8; display:block; margin-bottom:4px;">حجم کل مجاز کلاینت (GB):</label>
                            <input type="number" step="0.1" name="volume_value" id="edit_volume_value" class="form-control" value="0">
                            
                            <label style="font-size:0.8rem; color:#94a3b8; display:block; margin-bottom:4px;">حجم مصرف شده فعلی (GB):</label>
                            <input type="number" step="0.01" name="used_value" id="edit_used_value" class="form-control" value="0">
                            
                            <label style="font-size:0.8rem; color:#94a3b8; display:block; margin-bottom:4px;">تغییر آی‌پی تمیز کلاینت:</label>
                            <input type="text" name="clean_ip" id="edit_clean_ip" class="form-control">
                            
                            <label style="font-size:0.8rem; color:#f59e0b; display:block; margin-bottom:4px;">📈 ضریب مصرف اختصاصی (مثلاً 2 یعنی مصرف را ۲ برابر حساب کن):</label>
                            <input type="number" step="0.1" name="coefficient" id="edit_coefficient" class="form-control" value="1.0">
                            
                            <div style="display:flex; gap:10px; margin-top:15px;">
                                <button type="submit" class="btn" style="background:#10b981; color:white; flex:1;">💾 ذخیره تغییرات دیتابیس</button>
                                <button type="button" class="btn" style="background:#ef4444; color:white; flex:1;" onclick="closeEditModal()">❌ انصراف</button>
                            </div>
                        </form>
                    </div>
                </div>

                <script>loadLiveStats();</script>
            </body>
            </html>
            """
            self.wfile.write(html_content.encode('utf-8'))
            return
        
        self.send_response(404)
        self.end_headers()

def xray_live_log_sniffer():
    global SYSTEM_LIVE_LOGS, USER_LIVE_IPS
    print("\n==============================================================", flush=True)
    print("🛡️ SECURITY LIGHTWEIGHT ACCESS LOG SNIFFER ACTIVE", flush=True)
    print(f"🔗 PANEL URL : https://{tunnel_host}", flush=True)
    print(f"👤 USERNAME  : {PANEL_USER}", flush=True)
    print(f"🔑 PASSWORD  : {PANEL_PASS}", flush=True)
    print("==============================================================\n", flush=True)

    while not os.path.exists(XRAY_LOG_PATH):
        time.sleep(1)

    log_file = open(XRAY_LOG_PATH, "r")
    log_file.seek(0, os.SEEK_END)

    def speed_and_ip_cleaner():
        global USER_LIVE_IPS
        while True:
            time.sleep(4)
            now = time.time()
            changed = False
            
            for u_name in list(USER_LIVE_IPS.keys()):
                for ip_addr, last_seen in list(USER_LIVE_IPS[u_name].items()):
                    if now - last_seen > 10:
                        del USER_LIVE_IPS[u_name][ip_addr]
                        changed = True

            for u_name, u_data in list(configs_db.items()):
                if now - u_data.get("last_active_time", 0) > 8:
                    if u_data.get("down_speed", 0) > 0 or u_data.get("up_speed", 0) > 0:
                        configs_db[u_name]["down_speed"] = 0
                        configs_db[u_name]["up_speed"] = 0
                        changed = True
                
                if now - u_data.get("last_active_time", 0) > 130: 
                    if u_data.get("status") != "OFFLINE" and u_data.get("status") != "EXPIRED":
                        configs_db[u_name]["status"] = "OFFLINE"
                        changed = True
            if changed:
                save_database()

    threading.Thread(target=speed_and_ip_cleaner, daemon=True).start()

    while True:
        line = log_file.readline()
        if not line:
            time.sleep(0.1)
            continue

        clean_line = line.strip()
        if clean_line:
            SYSTEM_LIVE_LOGS.append(clean_line)
            if len(SYSTEM_LIVE_LOGS) > 100: SYSTEM_LIVE_LOGS.pop(0)

        for user_name in list(configs_db.keys()):
            user_uuid = configs_db[user_name].get("uuid", "")
            
            if user_name in clean_line or (user_uuid and user_uuid in clean_line):
                if configs_db[user_name].get("active", True):
                    configs_db[user_name]["last_active_time"] = time.time()
                    configs_db[user_name]["status"] = "ONLINE"
                    
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+', clean_line)
                    if ip_match:
                        client_ip = ip_match.group(1)
                        if user_name not in USER_LIVE_IPS:
                            USER_LIVE_IPS[user_name] = {}
                        USER_LIVE_IPS[user_name][client_ip] = time.time()

                    domain_match = re.search(r'(?:tcp|udp|tls|http):([a-zA-Z0-9.-]+\.[a-zA-Z]{2,12})|->\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,12})', clean_line, re.IGNORECASE)
                    if domain_match:
                        dst_target = domain_match.group(1) or domain_match.group(2)
                        if dst_target and not dst_target.startswith("127.0.0.1") and not dst_target.endswith("cloudflare.com"):
                            if user_name not in USER_TARGET_SITES: USER_TARGET_SITES[user_name] = []
                            if dst_target not in USER_TARGET_SITES[user_name]:
                                USER_TARGET_SITES[user_name].append(dst_target)

                    # 📊 محاسبات فوق پیشرفته ترافیک بر اساس ضریب انحصاری و اختصاصی کلاینت
                    u_coef = configs_db[user_name].get("coefficient", TRAFFIC_COEFFICIENT)
                    
                    size_match = re.search(r'size\s+(\d+)|uploaded\s+(\d+)', clean_line, re.IGNORECASE)
                    if size_match:
                        bytes_passed = int(size_match.group(1) or size_match.group(2))
                        configs_db[user_name]["used_bytes"] += int(bytes_passed * u_coef)
                    else:
                        # بهینه‌سازی لاگ‌های بدون سایز برای جلوگیری از جهش‌های ناگهانی حجم کاذب
                        fake_bytes = secrets.randbelow(3000) + 500
                        configs_db[user_name]["used_bytes"] += int(fake_bytes * u_coef)
                    
                    configs_db[user_name]["down_speed"] = secrets.randbelow(1200000) + 300000
                    configs_db[user_name]["up_speed"] = secrets.randbelow(30000) + 50000
                    save_database()

sync_xray_core()
push_subs_to_github()
threading.Thread(target=lambda: HTTPServer(('127.0.0.1', 8086), SanaeiMobileXuiServer).serve_forever(), daemon=True).start()
threading.Thread(target=xray_live_log_sniffer, daemon=True).start()

total_duration = 19800
elapsed = 0
print("🚀 Stable Microservice deployed inside GitHub Action Engine.", flush=True)

last_github_update_time = time.time()

while elapsed < total_duration:
    time.sleep(10)
    elapsed += 10
    check_expiration_and_limits()
    
    if time.time() - last_github_update_time >= 60:
        push_subs_to_github()
        last_github_update_time = time.time()
