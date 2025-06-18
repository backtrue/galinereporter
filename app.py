# -*- coding: utf-8 -*-
import os
import uuid
import requests
import time
from flask import Flask, redirect, request, session, url_for, render_template, flash, jsonify, Response
from dotenv import load_dotenv
from functools import wraps

# --- Stripe API ---
import stripe

STRIPE_SECRET_KEY = os.getenv('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY')
STRIPE_PRODUCT_ID = os.getenv('STRIPE_PRODUCT_ID', 'prod_SW1E7lkXsFUyf2')
STRIPE_PRICE_ID = os.getenv('STRIPE_PRICE_ID', 'price_0RazC8YDQY3sAQESAkflrTZC')
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET')

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

# --- Google API 相關 import ---
from google.oauth2.credentials import Credentials
from google.analytics.data_v1beta import BetaAnalyticsDataClient
from google.analytics.data_v1beta.types import RunReportRequest, Dimension, Metric, DateRange
from google.analytics.admin import AnalyticsAdminServiceClient
from google.api_core.exceptions import GoogleAPIError

# --- LINE Bot SDK import ---
from linebot import LineBotApi, WebhookHandler
from linebot.models import TextSendMessage
from linebot.exceptions import LineBotApiError

# --- 資料庫和加密 import ---
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import DateTime, String, Text, Boolean, Float
from cryptography.fernet import Fernet
import datetime
import traceback
import pytz

# --- Cloud SQL Connector import ---
from google.cloud.sql.connector import Connector, IPTypes
import sqlalchemy

# --- Click for Flask CLI ---
import click

# --- APScheduler for monthly jobs ---
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger


# --- 載入環境變數 ---
load_dotenv()

app = Flask(__name__)

# === Stripe 訂閱付款 API ===
from flask import abort

@app.route('/api/stripe/create-checkout-session', methods=['POST'])
def create_checkout_session():
    data = request.get_json() or {}
    customer_email = data.get('email')
    if not customer_email:
        return jsonify({'error': '缺少 email'}), 400
    # 1. 檢查 email 是否已註冊
    user = UserConfig.query.filter_by(google_email=customer_email).first()
    if not user:
        return jsonify({'error': '此 email 尚未註冊，請先註冊會員'}), 400
    # 2. 若未建立 Stripe customer，則建立並記錄
    if not user.stripe_customer_id:
        try:
            customer = stripe.Customer.create(email=customer_email)
            user.stripe_customer_id = customer.id
            db.session.commit()
        except Exception as e:
            return jsonify({'error': f'Stripe customer 建立失敗: {str(e)}'}), 500
    # 3. 計算 credits 折抵金額（1 credit = 10 JPY，最多 1500 JPY）
    discount_amount = min(user.credits * 10, 1500)
    coupon_id = None
    if discount_amount > 0:
        try:
            coupon = stripe.Coupon.create(
                amount_off=discount_amount,
                currency='jpy',
                duration='once',
                name=f'首月 credits 折抵 {discount_amount} JPY'
            )
            coupon_id = coupon.id
        except Exception as e:
            return jsonify({'error': f'Stripe coupon 建立失敗: {str(e)}'}), 500
    try:
        checkout_params = {
            'customer': user.stripe_customer_id,
            'payment_method_types': ['card'],
            'line_items': [{
                'price': STRIPE_PRICE_ID,
                'quantity': 1,
            }],
            'mode': 'subscription',
            'success_url': data.get('success_url', url_for('index', _external=True)),
            'cancel_url': data.get('cancel_url', url_for('index', _external=True)),
        }
        if coupon_id:
            checkout_params['discounts'] = [{'coupon': coupon_id}]
        checkout_session = stripe.checkout.Session.create(**checkout_params)
        return jsonify({'checkout_url': checkout_session.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# === Stripe Webhook ===
import json

# 檢查是否已經註冊過此路由，避免重複註冊
if 'handle_stripe_webhook' not in [rule.endpoint for rule in app.url_map.iter_rules()]:
    @app.route('/api/stripe/webhook', methods=['POST'])
    def handle_stripe_webhook():
        payload = request.data
        sig_header = request.headers.get('Stripe-Signature')
        event = None
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, STRIPE_WEBHOOK_SECRET
            )
        except ValueError as e:
            print(f"Webhook 錯誤: {e}")
            return 'Invalid payload', 400
        except stripe.error.SignatureVerificationError as e:
            print(f"Webhook 簽名驗證失敗: {e}")
            return 'Invalid signature', 400
    # 根據 event['type'] 處理對應事件
        if event['type'] == 'invoice.paid':
            print('訂閱付款成功', event['data']['object'])
            stripe_customer_id = event['data']['object']['customer']
            # 先找 user
            user = UserConfig.query.filter_by(stripe_customer_id=stripe_customer_id).first()
            if not user:
                # 若找不到，嘗試用 email 對應（第一次升級可能 stripe_customer_id 尚未寫入）
                invoice_email = event['data']['object'].get('customer_email')
                if not invoice_email and 'customer' in event['data']['object']:
                    # 進一步查詢 Stripe customer 資料
                    customer_obj = stripe.Customer.retrieve(stripe_customer_id)
                    invoice_email = customer_obj.email if customer_obj else None
                if invoice_email:
                    user = UserConfig.query.filter_by(google_email=invoice_email).first()
                    if user:
                        user.stripe_customer_id = stripe_customer_id
            if user:
                user.membership_type = 'pro'
                refill_credits(user)
                db.session.commit()
            else:
                print(f"找不到對應會員 (customer_id={stripe_customer_id})")
        elif event['type'] == 'invoice.payment_failed':
            print('訂閱付款失敗', event['data']['object'])
            stripe_customer_id = event['data']['object']['customer']
            user = UserConfig.query.filter_by(stripe_customer_id=stripe_customer_id).first()
            if user:
                # 進入待付款狀態，可自訂欄位或通知
                pass
        elif event['type'] == 'customer.subscription.deleted':
            print('訂閱取消', event['data']['object'])
            stripe_customer_id = event['data']['object']['customer']
            user = UserConfig.query.filter_by(stripe_customer_id=stripe_customer_id).first()
            if user:
                user.membership_type = 'free'
                db.session.commit()
        elif event['type'] == 'customer.subscription.updated':
            print('訂閱狀態更新', event['data']['object'])
            # 可根據狀態進一步同步會員狀態
        else:
            print(f"收到未處理的 Stripe event: {event['type']}")
        return '', 200
app.secret_key = os.getenv('FLASK_SECRET_KEY', os.urandom(24))

# --- 資料庫設定 (Cloud SQL) ---
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
INSTANCE_CONNECTION_NAME = os.getenv("INSTANCE_CONNECTION_NAME"); DB_USER = os.getenv("DB_USER", "postgres"); DB_PASS = os.getenv("DB_PASS"); DB_NAME = os.getenv("DB_NAME", "postgres")
db_engine = None
if all([INSTANCE_CONNECTION_NAME, DB_USER, DB_PASS, DB_NAME]):
    try:
        connector = Connector();
        def getconn(): return connector.connect(INSTANCE_CONNECTION_NAME, "pg8000", user=DB_USER, password=DB_PASS, db=DB_NAME, ip_type=IPTypes.PUBLIC)
        db_engine = sqlalchemy.create_engine("postgresql+pg8000://", creator=getconn, pool_size=5, pool_recycle=1800)
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = { "creator": getconn }; app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql+pg8000://{DB_USER}:{DB_PASS}@/{DB_NAME}"
        print("Cloud SQL 連線引擎準備完成。")
    except Exception as e_sql: print(f"建立 Cloud SQL 連線引擎失敗: {e_sql}"); traceback.print_exc()
else: print("警告：缺少 Cloud SQL 連線環境變數。"); basedir = os.path.abspath(os.path.dirname(__file__)); app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'fallback.db')
db = SQLAlchemy(app)

# --- 加密設定 ---
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY'); cipher_suite = None
if ENCRYPTION_KEY:
    try: cipher_suite = Fernet(ENCRYPTION_KEY.encode())
    except ValueError: print("警告：ENCRYPTION_KEY 格式錯誤！")
else: print("警告：未設定 ENCRYPTION_KEY！")

# --- 加密/解密輔助函式 ---
def encrypt_token(token):
    if not token or not cipher_suite: return token
    try: return cipher_suite.encrypt(token.encode()).decode()
    except Exception as e: print(f"加密錯誤: {e}"); return None
def decrypt_token(encrypted_token):
    if not encrypted_token or not cipher_suite: return encrypted_token
    try: return cipher_suite.decrypt(encrypted_token.encode()).decode()
    except Exception as e: print(f"解密錯誤: {e}"); return None

# --- 資料庫模型 ---
class UserConfig(db.Model):
    __tablename__ = 'user_configs'
    id = db.Column(db.Integer, primary_key=True)
    google_email = db.Column(String(255), nullable=False, unique=True, index=True)
    google_refresh_token_encrypted = db.Column(Text, nullable=True)
    line_user_id = db.Column(String(100), nullable=True, unique=False)
    ga_property_id = db.Column(String(50), nullable=True)
    ga_account_name = db.Column(String(255), nullable=True)
    ga_property_name = db.Column(String(255), nullable=True)
    timezone = db.Column(String(50), nullable=False, default='Asia/Taipei')
    is_active = db.Column(Boolean, nullable=False, default=True)
    is_admin = db.Column(Boolean, nullable=False, default=False)
    updated_at = db.Column(DateTime, nullable=False, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    # Stripe/會員制相關欄位
    stripe_customer_id = db.Column(String(100), nullable=True, unique=True, index=True)
    membership_type = db.Column(String(20), nullable=False, default='free')  # 'free' or 'pro'
    credits = db.Column(db.Integer, nullable=False, default=0)
    # Referral system
    referral_code = db.Column(String(32), nullable=True, unique=True, index=True)  # 自己的推薦碼
    referred_by = db.Column(String(32), nullable=True, index=True)  # 推薦人 referral_code
    referral_credits = db.Column(db.Integer, nullable=False, default=0)  # 累計因推薦獲得點數
    def __repr__(self):
        return f'<UserConfig Email:{self.google_email} Admin:{self.is_admin} Referral:{self.referral_code} ReferredBy:{self.referred_by}>'

# 推薦紀錄表
class ReferralLog(db.Model):
    __tablename__ = 'referral_logs'
    id = db.Column(db.Integer, primary_key=True)
    referrer_code = db.Column(String(32), nullable=False, index=True)  # 推薦人 referral_code
    referred_email = db.Column(String(255), nullable=False, index=True)  # 被推薦人 email
    credits_awarded = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    def __repr__(self):
        return f'<ReferralLog referrer:{self.referrer_code} referred:{self.referred_email} credits:{self.credits_awarded}>'

# 點數異動紀錄表
class CreditLog(db.Model):
    __tablename__ = 'credit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(String(255), nullable=False, index=True)
    change_type = db.Column(String(32), nullable=False)  # 來源/用途 e.g. 'refill', 'consume', 'admin', 'referral', 'stripe'
    delta = db.Column(db.Integer, nullable=False)  # 異動點數（正/負）
    balance = db.Column(db.Integer, nullable=False)  # 異動後餘額
    description = db.Column(String(255), nullable=True)
    created_at = db.Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    def __repr__(self):
        return f'<CreditLog {self.user_email} {self.change_type} {self.delta} {self.balance}>'


class ReportSnapshot(db.Model):
    __tablename__ = 'report_snapshots'; id = db.Column(db.Integer, primary_key=True); config_id = db.Column(db.Integer, db.ForeignKey('user_configs.id'), nullable=False); snapshot_datetime_utc = db.Column(DateTime, nullable=False, default=datetime.datetime.utcnow); report_for_date = db.Column(String(10), nullable=False); report_for_timeslot = db.Column(String(20), nullable=False); sessions = db.Column(db.Integer, nullable=True); total_revenue = db.Column(db.Float, nullable=True); created_at = db.Column(DateTime, nullable=False, default=datetime.datetime.utcnow); user_config = db.relationship('UserConfig', backref=db.backref('report_snapshots_backref', lazy='dynamic'))
    def __repr__(self): return f'<ReportSnapshot ID:{self.id} ForDate:{self.report_for_date} Slot:{self.report_for_timeslot}>'

# --- Credits 操作 function ---
PRO_CREDITS_MONTHLY = 150
FREE_SIGNUP_CREDITS = 0  # 可由管理員調整
RECOMMEND_CREDITS = 20   # 可由管理員調整
REFERRAL_AWARD_CREDITS = 20  # 推薦獎勵點數

import secrets

def get_or_create_referral_code(user):
    if not user.referral_code:
        # 產生唯一推薦碼
        while True:
            code = secrets.token_urlsafe(8)[:12]
            if not UserConfig.query.filter_by(referral_code=code).first():
                user.referral_code = code
                db.session.commit()
                break
    return user.referral_code

# 補滿所有 pro 會員 credits（每月 1 號自動補滿）
def refill_all_pro_members_credits():
    with app.app_context():
        pro_users = UserConfig.query.filter_by(membership_type='pro').all()
        count_refilled = 0
        for user in pro_users:
            if user.credits < PRO_CREDITS_MONTHLY:
                user.credits = PRO_CREDITS_MONTHLY
                db.session.commit()
                print(f"[排程] 會員 {user.google_email} credits 補滿至 {PRO_CREDITS_MONTHLY}")
                count_refilled += 1
        print(f"[排程] 本次共補滿 {count_refilled} 位 pro 會員 credits")
    return count_refilled

def log_credit_change(user, delta, change_type, description=None):
    # 寫入 CreditLog
    log = CreditLog(
        user_email=user.google_email,
        change_type=change_type,
        delta=delta,
        balance=user.credits,
        description=description
    )
    db.session.add(log)
    db.session.commit()

def refill_credits(user: UserConfig, amount=PRO_CREDITS_MONTHLY):
    if user.membership_type == 'pro' and (user.credits < amount):
        delta = amount - user.credits
        user.credits = amount
        log_credit_change(user, delta, 'refill', f"Pro 會員補滿至 {amount}")
        print(f"[補滿] 會員 {user.google_email} credits 補滿至 {amount}")
        return True
    return False

# 通知 credits 不足的會員
def notify_low_credits():
    with app.app_context():
        # 設定低點數閾值
        LOW_CREDITS_THRESHOLD = 10

        # 查找 credits 不足的活躍會員
        low_credit_users = UserConfig.query.filter(
            UserConfig.credits <= LOW_CREDITS_THRESHOLD,
            UserConfig.is_active == True
        ).all()

        notified_count = 0
        for user in low_credit_users:
            # 這裡可以實作 LINE 通知或其他通知方式
            print(f"[通知] 會員 {user.google_email} credits 不足，剩餘: {user.credits}")
            notified_count += 1

        print(f"[排程] 本次共通知 {notified_count} 位會員 credits 不足")
    return notified_count

# 加點（管理員或推薦等用途）
def add_credits(user: UserConfig, count, change_type='admin', description=None):
    user.credits += count
    db.session.commit()
    print(f"會員 {user.google_email} 增加 {count} credits，剩餘 {user.credits}")
    log_credit_change(user, count, change_type, description or '管理員/推薦/Stripe 增加')

# --- 在應用程式初始化時嘗試建立資料庫表格 ---
with app.app_context():
    print("應用程式啟動：檢查並建立資料庫表格..."); db.create_all(); print("應用程式啟動：資料庫表格檢查/建立完畢。")

# 啟動 APScheduler 並註冊任務（移到 app_context 外）
scheduler = BackgroundScheduler(timezone='Asia/Taipei')
scheduler.add_job(refill_all_pro_members_credits, 'cron', day=1, hour=0, minute=0, id='monthly_refill')
scheduler.add_job(notify_low_credits, 'cron', hour=10, minute=0, id='low_credits_notify')
scheduler.start()
print("APScheduler 啟動，已註冊每月 1 號自動補滿 pro 會員 credits 任務和低點數通知任務。")

# Define start_scheduler to prevent NameError
def start_scheduler():
    pass

try:
    start_scheduler()
except Exception as e:
    print(f"APScheduler 啟動失敗: {e}")

# --- Google/LINE OAuth/Bot 設定 ---
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID'); GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET'); GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"; # 自動檢測環境來設定正確的重新導向 URI
if os.getenv('REPL_OWNER') and os.getenv('REPL_SLUG'):
    # Preview 模式
    preview_url = f"https://{os.getenv('REPL_SLUG')}--{os.getenv('REPL_OWNER')}.repl.co"
    default_redirect_uri = f"{preview_url}/google-callback"
else:
    # Production 模式
    default_redirect_uri = 'https://galinereporter--backtrue.repl.co/google-callback'

GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', default_redirect_uri); GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"
LINE_CHANNEL_ID = os.getenv('LINE_CHANNEL_ID'); LINE_CHANNEL_SECRET = os.getenv('LINE_CHANNEL_SECRET'); 
# 設定 LINE 重新導向 URI，支援 preview 和 production 模式
if os.getenv('REPL_OWNER') and os.getenv('REPL_SLUG'):
    # Preview 模式
    default_line_redirect_uri = f"{preview_url}/line-callback"
else:
    # Production 模式
    default_line_redirect_uri = 'https://galinereporter--backtrue.repl.co/line-callback'

LINE_REDIRECT_URI = os.getenv('LINE_REDIRECT_URI', default_line_redirect_uri)
LINE_CHANNEL_ACCESS_TOKEN = os.getenv('LINE_CHANNEL_ACCESS_TOKEN')
SCHEDULER_SECRET_TOKEN = os.getenv('SCHEDULER_SECRET_TOKEN')

# --- 管理員認證 Decorator ---
def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin_email = session.get('current_user_google_email')
        if not admin_email: flash("請先使用您的 Google 管理員帳號登入以存取此頁面。", "warning"); session['next_url'] = request.url; return redirect(url_for('login_google'))
        with app.app_context(): user_config = UserConfig.query.filter_by(google_email=admin_email).first()
        if not user_config or not user_config.is_admin: flash("您的帳號沒有管理員權限。", "error"); return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# === Helper Function: Get Google Access Token (已修正所有 SyntaxError) ===
def get_google_access_token(user_config_id=None, user_email=None):
    # ... (此函式與上一完整版相同，已修正所有 SyntaxError) ...
    with app.app_context(): config_to_use = None
    if user_config_id: config_to_use = UserConfig.query.get(user_config_id)
    elif user_email: config_to_use = UserConfig.query.filter_by(google_email=user_email).first()
    if not config_to_use or not config_to_use.google_refresh_token_encrypted: identifier = user_config_id if user_config_id else user_email; print(f"DB錯誤：找不到使用者 {identifier} 的設定或缺少 Token。"); return None
    encrypted_token = config_to_use.google_refresh_token_encrypted; refresh_token = decrypt_token(encrypted_token)
    if not refresh_token: print(f"錯誤：無法解密使用者 {identifier} 的 Token"); return None
    print(f"正在使用使用者 {config_to_use.google_email} 的 Refresh Token 換取 Access Token..."); payload = {'client_id': GOOGLE_CLIENT_ID, 'client_secret': GOOGLE_CLIENT_SECRET, 'refresh_token': refresh_token, 'grant_type': 'refresh_token'}
    response = None
    try:
        response = requests.post(GOOGLE_TOKEN_URI, data=payload); response.raise_for_status(); token_data = response.json(); access_token = token_data.get('access_token'); return access_token
    except requests.exceptions.RequestException as e:
        print(f"交換 Access Token 失敗 (使用者 {config_to_use.google_email}): {e}")
        if response is not None:
            print(f"錯誤回應 Body: {response.text}")
            if response.status_code in [400, 401]:
                print(f"Refresh Token (使用者 {config_to_use.google_email}) 失效，正清除...");
                with app.app_context(): db_config_to_clear = UserConfig.query.get(config_to_use.id);
                if db_config_to_clear: db_config_to_clear.google_refresh_token_encrypted = None; db.session.commit(); print("DB Token 已清除。")
                if request: flash("Google 憑證已失效，請重新登入。", "error")
            elif request: flash(f"無法更新 Google 憑證 (Status: {response.status_code})。", "error")
        elif request: flash("無法連接 Google 更新憑證。", "error")
        return None
    except Exception as e:
        print(f"處理 Token 交換未知錯誤: {e}")
        if request: flash("處理 Google 憑證錯誤。", "error")
        return None

# === Helper Function: Get Accessible GA Properties ===
def get_ga_properties_from_db(user_email=None):
    # ... (此函式與上一完整版相同) ...
    properties_list = []; error_message = None; detailed_list = []
    if not user_email: return properties_list, "未提供使用者 Email", detailed_list
    access_token = get_google_access_token(user_email=user_email)
    if not access_token: return [], "無法取得 Google Access Token", detailed_list
    try: credentials = Credentials(token=access_token); client = AnalyticsAdminServiceClient(credentials=credentials); results = client.list_account_summaries()
    except GoogleAPIError as e: print(f"呼叫 GA Admin API 失敗: {e}"); error_message = f"無法取得 GA 資源清單: {e.message}"; return [], error_message, detailed_list
    except Exception as e: print(f"處理 Admin API 回應未知錯誤: {e}\n{traceback.format_exc()}"); error_message = f"取得 GA 資源時發生內部錯誤: {e}"; return [], error_message, detailed_list
    for account_summary in results:
        account_name_raw = account_summary.display_name
        if hasattr(account_summary, 'property_summaries'):
             for prop_summary in account_summary.property_summaries:
                 prop_id_full = prop_summary.property; prop_id_numeric = prop_id_full.split('/')[-1]; property_name_raw = prop_summary.display_name
                 if prop_id_full.startswith("properties/"):
                     display_name_for_dropdown = f"{property_name_raw} ({prop_id_numeric}) - [帳號: {account_name_raw}]"
                     properties_list.append({'id': prop_id_numeric, 'name': display_name_for_dropdown})
                     detailed_list.append({'id': prop_id_numeric, 'property_name_raw': property_name_raw, 'account_name_raw': account_name_raw})
    if not properties_list: error_message = "找不到 GA4 資源。"
    session['ga_detailed_properties'] = detailed_list
    return properties_list, error_message, detailed_list

# ====[核心報表任務函式]====
def run_and_send_report(user_config_id, date_mode='yesterday'):
    # ... (此函式與上一完整版相同) ...
    print(f"\n--- 報表任務觸發 (Config ID: {user_config_id}, Mode: {date_mode}) ---")
    with app.app_context():
        config = UserConfig.query.get(user_config_id);
        if not config or not config.is_active: print(f"設定 ID {user_config_id} 不存在或未啟用，任務取消。"); return
        property_id = config.ga_property_id; line_user_id = config.line_user_id; user_timezone_str = 'Asia/Taipei'
        if not all([property_id, line_user_id, config.google_refresh_token_encrypted, LINE_CHANNEL_ACCESS_TOKEN, user_timezone_str]): print(f"設定 ID {user_config_id} 缺少必要資訊，任務取消。"); return
        print("任務：取得 Access Token..."); access_token = get_google_access_token(user_config_id=config.id)
        if not access_token: print("任務：無法取得 Access Token，任務失敗。"); return
        try:
            credentials = Credentials(token=access_token); client = BetaAnalyticsDataClient(credentials=credentials)
            try: user_tz = pytz.timezone(user_timezone_str)
            except pytz.exceptions.UnknownTimeZoneError: print(f"錯誤：指定的時區 '{user_timezone_str}' 無效，改用 UTC。"); user_tz = pytz.utc
            now_in_user_tz = datetime.datetime.now(user_tz); today_in_user_tz = now_in_user_tz.date(); current_hour_in_user_tz = now_in_user_tz.hour
            target_date = today_in_user_tz - datetime.timedelta(days=1) if date_mode == 'yesterday' else today_in_user_tz
            target_date_str = target_date.strftime('%Y-%m-%d'); report_timeslot_str = f"{current_hour_in_user_tz:02d}:00_{date_mode}"
            print(f"任務：請求 GA Property {property_id} ({date_mode}，基於時區 {user_timezone_str})，請求日期: {target_date_str}...")
            request_params = RunReportRequest(property=f"properties/{property_id}", dimensions=[Dimension(name="date")], metrics=[Metric(name="sessions"), Metric(name="totalRevenue")], date_ranges=[DateRange(start_date=target_date_str, end_date=target_date_str)])
            response = client.run_report(request_params); print("任務：收到 GA API 回應。")
            sessions_val_str = "0"; revenue_val_str = "0.00"; report_date_str_from_ga = target_date_str; current_sessions = 0; current_revenue = 0.0
            if response.row_count > 0:
                row = response.rows[0]
                if row.dimension_values: report_date_str_from_ga = row.dimension_values[0].value
                sessions_val_str = row.metric_values[0].value; revenue_val_str = row.metric_values[1].value
            current_sessions = int(sessions_val_str) if sessions_val_str.isdigit() else 0
            try: current_revenue = float(revenue_val_str)
            except ValueError: current_revenue = 0.0
            revenue_display_str = f"{current_revenue:.2f}"
            print(f"任務：當期數據 - 日期: {report_date_str_from_ga}, 工作階段: {current_sessions}, 總收益: {revenue_display_str}")
            try:
                new_snapshot = ReportSnapshot(config_id=config.id, report_for_date=report_date_str_from_ga, report_for_timeslot=report_timeslot_str, sessions=current_sessions, total_revenue=current_revenue)
                db.session.add(new_snapshot); db.session.commit(); print(f"任務：成功儲存報表快照。ID: {new_snapshot.id}")
            except Exception as e_db_save: db.session.rollback(); print(f"任務：儲存報表快照失敗: {e_db_save}\n{traceback.format_exc()}")
            if response.row_count == 0: print(f"任務：報表沒有資料 (請求日期: {target_date_str})。")
            avg_sessions_str = "N/A"; avg_revenue_str = "N/A"; sessions_insight = ""; revenue_insight = ""
            end_date_for_avg = target_date - datetime.timedelta(days=1); start_date_for_avg = end_date_for_avg - datetime.timedelta(days=6)
            historical_snapshots = ReportSnapshot.query.filter(ReportSnapshot.config_id == config.id, ReportSnapshot.report_for_timeslot == report_timeslot_str, ReportSnapshot.report_for_date >= start_date_for_avg.strftime('%Y-%m-%d'), ReportSnapshot.report_for_date <= end_date_for_avg.strftime('%Y-%m-%d')).all()
            if historical_snapshots:
                total_hist_sessions = sum(s.sessions for s in historical_snapshots if s.sessions is not None)
                total_hist_revenue = sum(s.total_hist_revenue for s in historical_snapshots if s.total_revenue is not None)
                count_hist_days = len(historical_snapshots)
                avg_sessions = total_hist_sessions / count_hist_days if count_hist_days > 0 else 0; avg_revenue = total_hist_revenue / count_hist_days if count_hist_days > 0 else 0.0
                avg_sessions_str = f"{avg_sessions:.0f}"; avg_revenue_str = f"{avg_revenue:.2f}"
                if current_sessions > avg_sessions * 1.05: sessions_insight = " (📈 高於平均)"
                elif current_sessions < avg_sessions * 0.95: sessions_insight = " (📉 低於平均)"
                else: sessions_insight = " (平穩)"
                if current_revenue > avg_revenue * 1.05: revenue_insight = " (📈 高於平均)"
                elif current_revenue < avg_revenue * 0.95: revenue_insight = " (📉 低於平均)"
                else: revenue_insight = " (平穩)"
                print(f"任務：過去七日同時段平均 - 工作階段: {avg_sessions_str}, 總收益: {avg_revenue_str}")
            else: print(f"任務：找不到過去七日同時段 ({report_timeslot_str}) 的歷史數據。")
            display_date_for_title = report_date_str_from_ga
            report_title = f"GA4 {'昨日' if date_mode == 'yesterday' else '今日'}速報 ({display_date_for_title})"; line_message_content = f"📊 {report_title}\n\n工作階段: {current_sessions}{sessions_insight}\n(七日均: {avg_sessions_str})\n\n總收益: {revenue_display_str}{revenue_insight}\n(七日均: {avg_revenue_str})"
            try: print(f"任務：準備發送 LINE 給 {line_user_id}"); line_bot_api = LineBotApi(LINE_CHANNEL_ACCESS_TOKEN); line_bot_api.push_message(line_user_id, TextSendMessage(text=line_message_content)); print("任務：成功發送 LINE。")
            except LineBotApiError as e: print(f"任務：發送 LINE 失敗: Status={e.status_code}, Body={e.error.message}")
            except Exception as e_line: print(f"任務：發送 LINE 時未知錯誤: {e_line}\n{traceback.format_exc()}")
        except GoogleAPIError as e: print(f"任務：呼叫 GA Data API 錯誤 (Property: {property_id}, Date: {target_date_str}): {e}\n{traceback.format_exc()}")
        except Exception as e: print(f"任務：執行時未知錯誤 (Property: {property_id}, Date: {target_date_str}): {e}\n{traceback.format_exc()}")
    print(f"--- 報表任務結束 (Config ID: {user_config_id}, Mode: {date_mode}) ---")

# === Routes ===
@app.route('/')
def index(): # 儀表板 (修正 NameError)
    current_user_email = session.get('current_user_google_email') # 提前獲取 email
    config = None
    if current_user_email:
        # --- 修正 SyntaxError: with app.app_context() 移到下一行並縮排 ---
        with app.app_context():
            config = UserConfig.query.filter_by(google_email=current_user_email).first()

    google_linked = bool(config and config.google_refresh_token_encrypted)
    line_linked = bool(config and config.line_user_id)
    ga_property_set = bool(config and config.ga_property_id)

    ga_properties = []; ga_list_error = None; show_ga_selector = False
    if google_linked and not ga_property_set:
        if current_user_email: # 確保 email 存在才查詢
            show_ga_selector = True
            ga_properties_for_dropdown, ga_list_error, _ = get_ga_properties_from_db(user_email=current_user_email)
            ga_properties = ga_properties_for_dropdown
            if ga_list_error: flash(f"讀取 GA 資源清單錯誤: {ga_list_error}", "error")
        else: flash("無法識別您的 Google 帳號，請嘗試重新連結 Google 以選擇 GA 資源。", "warning"); show_ga_selector = False

    report_result = session.pop('ga_report_test_result', None)
    access_token_result = session.pop('google_access_token_test_result', None)

    return render_template('dashboard.html',
                           google_linked=google_linked, line_linked=line_linked, ga_property_set=ga_property_set,
                           show_ga_selector=show_ga_selector, ga_properties=ga_properties, ga_list_error=ga_list_error,
                           config=config,
                           credits_logs=CreditLog.query.filter_by(user_email=config.google_email).order_by(CreditLog.created_at.desc()).limit(10).all() if config else [],
                           referral_code=get_or_create_referral_code(config) if config else None,
                           referral_logs=ReferralLog.query.filter_by(referrer_code=config.referral_code).order_by(ReferralLog.created_at.desc()).limit(10).all() if config and config.referral_code else [],
                           ga_report_test_result=report_result,
                           google_user_email_debug=current_user_email,
                           google_access_token_test_result=access_token_result)

# ... (其他所有路由 @app.route('/settings') 到 @app.route('/test-ga-report-manual/<date_mode>') 與上一版相同，此處省略) ...

# === 推薦系統 API ===
from flask import g

@app.route('/api/referral/logs', methods=['GET'])
def api_get_referral_logs():
    current_user_email = session.get('current_user_google_email')
    if not current_user_email:
        return jsonify({"error": "請先登入"}), 401
    user = UserConfig.query.filter_by(google_email=current_user_email).first()
    if not user:
        return jsonify({"error": "找不到用戶"}), 404
    code = get_or_create_referral_code(user)
    logs = ReferralLog.query.filter_by(referrer_code=code).order_by(ReferralLog.created_at.desc()).all()
    result = [{
        "referred_email": log.referred_email,
        "credits_awarded": log.credits_awarded,
        "created_at": log.created_at.strftime('%Y-%m-%d %H:%M:%S')
    } for log in logs]
    return jsonify(result)

@app.route('/api/referral/my-code', methods=['GET'])
def api_get_my_referral_code():
    current_user_email = session.get('current_user_google_email')
    if not current_user_email:
        return jsonify({"error": "請先登入"}), 401
    user = UserConfig.query.filter_by(google_email=current_user_email).first()
    if not user:
        return jsonify({"error": "找不到用戶"}), 404
    code = get_or_create_referral_code(user)
    referral_url = url_for('index', _external=True) + f'?ref={code}'
    return jsonify({"referral_code": code, "referral_url": referral_url})

@app.route('/api/referral/bind', methods=['POST'])
def api_bind_referral():
    current_user_email = session.get('current_user_google_email')
    if not current_user_email:
        return jsonify({"error": "請先登入"}), 401
    user = UserConfig.query.filter_by(google_email=current_user_email).first()
    if not user:
        return jsonify({"error": "找不到用戶"}), 404
    if user.referred_by:
        return jsonify({"error": "已經綁定過推薦人，無法再次綁定"}), 400
    data = request.get_json() or {}
    code = data.get('referral_code')
    if not code:
        return jsonify({"error": "缺少推薦碼"}), 400
    referrer = UserConfig.query.filter_by(referral_code=code).first()
    if not referrer or referrer.google_email == current_user_email:
        return jsonify({"error": "推薦碼無效或不能推薦自己"}), 400
    user.referred_by = code
    db.session.commit()
    return jsonify({"success": True, "referred_by": code})

# === Stripe 購買 credits API ===
@app.route('/api/stripe/create-credit-session', methods=['POST'])
def create_credit_checkout_session():
    current_user_email = session.get('current_user_google_email')
    if not current_user_email:
        return jsonify({"error": "請先登入"}), 401
    data = request.get_json() or {}
    credits = int(data.get('credits', 0))
    if credits not in [50, 100, 200, 500]:
        return jsonify({"error": "僅支援購買 50/100/200 點"}), 400
    user = UserConfig.query.filter_by(google_email=current_user_email).first()
    if not user:
        return jsonify({"error": "找不到用戶"}), 404
    # 根據會員身份決定單價
    if user.membership_type == 'pro':
        unit_price = 10  # JPY
    else:
        unit_price = 20  # JPY
    amount_jpy = credits * unit_price
    try:
        checkout_session = stripe.checkout.Session.create(
            customer_email=current_user_email,
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'jpy',
                    'unit_amount': amount_jpy,
                    'product_data': {
                        'name': f'購買 {credits} 點數',
                    },
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=data.get('success_url', url_for('index', _external=True)),
            cancel_url=data.get('cancel_url', url_for('index', _external=True)),
            metadata={
                'credits': credits,
                'purchase_type': 'credits',
                'email': current_user_email,
                'unit_price': unit_price,
                'membership_type': user.membership_type
            }
        )
        return jsonify({
            'checkout_url': checkout_session.url,
            'unit_price': unit_price,
            'total_price': amount_jpy,
            'membership_type': user.membership_type
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# === Stripe Webhook 補強推薦獎勵 ===
# 此路由已在上方定義，移除重複

# === 點數異動紀錄查詢 API ===
@app.route('/api/credit/logs', methods=['GET'])
def api_get_credit_logs():
    current_user_email = session.get('current_user_google_email')
    if not current_user_email:
        return jsonify({"error": "請先登入"}), 401
    logs = CreditLog.query.filter_by(user_email=current_user_email).order_by(CreditLog.created_at.desc()).all()
    result = [{
        "change_type": log.change_type,
        "delta": log.delta,
        "balance": log.balance,
        "description": log.description,
        "created_at": log.created_at.strftime('%Y-%m-%d %H:%M:%S')
    } for log in logs]
    return jsonify(result)

# === 管理員 credits 異動紀錄查詢 ===
@app.route('/admin/credit/logs', methods=['GET'])
@admin_login_required
def admin_credit_logs():
    # 支援查詢參數：email, type, start, end, page, per_page
    email = request.args.get('email')
    change_type = request.args.get('type')
    start = request.args.get('start')
    end = request.args.get('end')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    q = CreditLog.query
    if email:
        q = q.filter(CreditLog.user_email == email)
    if change_type:
        q = q.filter(CreditLog.change_type == change_type)
    if start:
        q = q.filter(CreditLog.created_at >= start)
    if end:
        q = q.filter(CreditLog.created_at <= end)
    q = q.order_by(CreditLog.created_at.desc())
    logs = q.paginate(page=page, per_page=per_page, error_out=False)
    result = [{
        "user_email": log.user_email,
        "change_type": log.change_type,
        "delta": log.delta,
        "balance": log.balance,
        "description": log.description,
        "created_at": log.created_at.strftime('%Y-%m-%d %H:%M:%S')
    } for log in logs.items]
    return jsonify({
        "total": logs.total,
        "page": page,
        "per_page": per_page,
        "logs": result
    })

# === 管理員推薦紀錄查詢 ===
@app.route('/admin/referral/logs', methods=['GET'])
@admin_login_required
def admin_referral_logs():
    # 支援查詢參數：referrer_code, referred_email, start, end, page, per_page
    referrer_code = request.args.get('referrer_code')
    referred_email = request.args.get('referred_email')
    start = request.args.get('start')
    end = request.args.get('end')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    q = ReferralLog.query
    if referrer_code:
        q = q.filter(ReferralLog.referrer_code == referrer_code)
    if referred_email:
        q = q.filter(ReferralLog.referred_email == referred_email)
    if start:
        q = q.filter(ReferralLog.created_at >= start)
    if end:
        q = q.filter(ReferralLog.created_at <= end)
    q = q.order_by(ReferralLog.created_at.desc())
    logs = q.paginate(page=page, per_page=per_page, error_out=False)
    result = [{
        "referrer_code": log.referrer_code,
        "referred_email": log.referred_email,
        "credits_awarded": log.credits_awarded,
        "created_at": log.created_at.strftime('%Y-%m-%d %H:%M:%S')
    } for log in logs.items]
    return jsonify({
        "total": logs.total,
        "page": page,
        "per_page": per_page,
        "logs": result
    })

# === Bravo Brevo SMTP 郵件發送輔助函式 ===
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from apscheduler.schedulers.background import BackgroundScheduler
import datetime

def send_email_via_bravo(to, subject, body, html=False):
    smtp_host = 'smtp-relay.brevo.com'
    smtp_port = 587
    smtp_user = '68287d002@smtp-brevo.com'
    smtp_pass = '834JGkPLB5qMQX9f'
    from_addr = smtp_user
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to if isinstance(to, str) else ','.join(to)
    msg['Subject'] = subject
    if html:
        msg.attach(MIMEText(body, 'html', 'utf-8'))
    else:
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(from_addr, [to] if isinstance(to, str) else to, msg.as_string())
        return True
    except Exception as e:
        print(f"[SMTP] 郵件發送失敗: {e}")
        return False

# === LINE 優先通知（失敗自動 fallback email） ===
def send_message_to_user(user, subject, body, html=False):
    """
    user: UserConfig 實例
    subject: 郵件主旨（LINE 不顯示）
    body: 訊息內容
    html: 是否為 HTML 郵件內容
    """
    line_sent = False
    # 1. 嘗試發送 LINE（如有 line_user_id）
    if getattr(user, 'line_user_id', None):
        try:
            line_api = LineBotApi(os.getenv('LINE_CHANNEL_ACCESS_TOKEN'))
            # LINE 僅支援純文字
            line_api.push_message(user.line_user_id, TextSendMessage(text=body))
            line_sent = True
        except Exception as e:
            print(f"[LINE] 發送失敗: {e}")
    # 2. 若 LINE 失敗或未綁定，改發 email
    if not line_sent:
        print(f"[通知] 改用 email 發送給 {user.google_email}")
        send_email_via_bravo(user.google_email, subject, body, html=html)

# === credits 快用完自動提醒任務 ===
def notify_low_credits():
    with app.app_context():
        users = UserConfig.query.filter(UserConfig.credits < 10).all()
        for user in users:
            msg = (
                "【點數即將用完提醒】\n\n"
                "您的會員點數已低於 10 點，請盡快於會員中心購買補充，避免服務中斷。"
            )
            send_message_to_user(user, "點數即將用完提醒", msg)

# === 管理員手動補滿 pro 會員 credits API ===
@app.route('/admin/refill-pro-credits', methods=['POST'])
@admin_login_required
def admin_refill_pro_credits():
    try:
        count = refill_all_pro_members_credits()
        return jsonify({"status": "success", "message": f"已補滿 {count} 位 pro 會員 credits"})
    except Exception as e:
        print(f"管理員手動補滿發生錯誤: {e}")
        return jsonify({"status": "error", "message": str(e)})

@app.route('/member-area')
def member_area():
    current_user_email = session.get('google_email')
    if not current_user_email:
        flash('請先登入 Google 帳號。', 'warning')
        return redirect(url_for('login_google'))

    config = UserConfig.query.filter_by(google_email=current_user_email).first()
    if not config:
        flash('找不到您的設定，請重新連結 Google 帳號。', 'error')
        return redirect(url_for('login_google'))

    # 取得推薦碼
    referral_code = get_or_create_referral_code(config)

    # 取得點數異動紀錄（增加到 10 筆）
    credits_logs = CreditLog.query.filter_by(user_email=config.google_email)\
                                 .order_by(CreditLog.created_at.desc())\
                                 .limit(10).all()

    # 取得推薦獎勵紀錄（增加到 10 筆）
    referral_logs = ReferralLog.query.filter_by(referrer_code=config.referral_code)\
                                    .order_by(ReferralLog.created_at.desc())\
                                    .limit(10).all() if config.referral_code else []

    return render_template('member_area.html',
                         config=config,
                         referral_code=referral_code,
                         credits_logs=credits_logs,
                         referral_logs=referral_logs,
                         REFERRAL_AWARD_CREDITS=REFERRAL_AWARD_CREDITS)

@app.route('/settings')
def settings():
    current_user_email = session.get('current_user_google_email')
    if not current_user_email: flash("請先透過 Google 登入以進行設定。", "warning"); return redirect(url_for('index'))
    with app.app_context(): config = UserConfig.query.filter_by(google_email=current_user_email).first()
    ga_properties = []; ga_list_error = None; show_ga_selector = False; google_linked = bool(config and config.google_refresh_token_encrypted); line_linked = bool(config and config.line_user_id);
    if google_linked:
        show_ga_selector = True; ga_properties_for_dropdown, ga_list_error, _ = get_ga_properties_from_db(user_email=current_user_email);
        ga_properties = ga_properties_for_dropdown
        if ga_list_error: flash(f"讀取 GA 資源清單時發生錯誤: {ga_list_error}", "error")
    access_token_result = session.pop('google_access_token_test_result', None)
    return render_template('settings.html',
                           google_linked=google_linked, line_linked=line_linked, show_ga_selector=show_ga_selector,
                           ga_properties=ga_properties, ga_list_error=ga_list_error, config=config,
                           google_user_email_debug=current_user_email,
                           google_access_token_test_result=access_token_result)

from google_auth_oauthlib.flow import Flow
from oauthlib.oauth2 import WebApplicationClient

# --- Google OAuth 設定 ---
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid_configuration"

# 統一的 OAuth scope 設定
OAUTH_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email", 
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/analytics.readonly"
]

# OAuth2 流程設定
def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

def init_oauth_flow():
    """初始化 OAuth2 流程"""
    google_provider_cfg = get_google_provider_cfg()
    client = WebApplicationClient(GOOGLE_CLIENT_ID)
    return client, google_provider_cfg

@app.route('/login/google')
def google_login():
    """Google OAuth 登入"""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash('Google OAuth 尚未設定，請聯繫管理員。', 'error')
        return redirect(url_for('index'))

    try:
        client, google_provider_cfg = init_oauth_flow()
        authorization_endpoint = google_provider_cfg["authorization_endpoint"]

        # 使用 HTTPS redirect_uri
        redirect_uri = url_for('google_callback', _external=True)
        if redirect_uri.startswith('http://'):
            redirect_uri = redirect_uri.replace('http://', 'https://', 1)

        # 將 scope 排序以確保一致性
        sorted_scopes = sorted(OAUTH_SCOPES)

        # 構建授權 URL
        request_uri = client.prepare_request_uri(
            authorization_endpoint,
            redirect_uri=redirect_uri,
            scope=sorted_scopes,
            access_type="offline",
            prompt="consent"
        )

        # 儲存 scope 到 session 以便後續驗證
        session['oauth_scopes'] = ' '.join(sorted_scopes)

        return redirect(request_uri)
    except Exception as e:
        print(f"Google 登入錯誤: {e}")
        traceback.print_exc()
        flash('Google 登入發生錯誤，請稍後再試。', 'error')
        return redirect(url_for('index'))

@app.route('/login/google/callback')
def google_callback():
    """Google OAuth 回調處理"""
    try:
        # 檢查是否有錯誤參數
        error = request.args.get('error')
        if error:
            flash(f'Google 登入被取消或發生錯誤: {error}', 'error')
            return redirect(url_for('index'))

        # 檢查必要參數
        code = request.args.get('code')
        if not code:
            flash('授權碼缺失，請重新登入。', 'error')
            return redirect(url_for('index'))

        client, google_provider_cfg = init_oauth_flow()
        token_endpoint = google_provider_cfg["token_endpoint"]

        # 確保 redirect_uri 使用 HTTPS
        redirect_uri = url_for('google_callback', _external=True)
        if redirect_uri.startswith('http://'):
            redirect_uri = redirect_uri.replace('http://', 'https://', 1)

        # 確保 authorization_response 使用 HTTPS
        authorization_response = request.url
        if authorization_response.startswith('http://'):
            authorization_response = authorization_response.replace('http://', 'https://', 1)

        # 準備 token 請求
        token_url, headers, body = client.prepare_token_request(
            token_endpoint,
            authorization_response=authorization_response,
            redirect_url=redirect_uri,
            code=code
        )

        # 獲取 token
        token_response = requests.post(
            token_url,
            headers=headers,
            data=body,
            auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
            timeout=30
        )

        if token_response.status_code != 200:
            print(f"Token 請求失敗: {token_response.status_code}, {token_response.text}")
            flash('獲取訪問令牌失敗，請重新登入。', 'error')
            return redirect(url_for('index'))

        # 解析 token
        token_data = token_response.json()
        client.parse_request_body_response(token_response.text)

        # 驗證 scope（如果 session 中有記錄的話）
        if 'oauth_scopes' in session:
            returned_scope = token_data.get('scope', '')
            expected_scopes = set(session['oauth_scopes'].split())
            returned_scopes = set(returned_scope.split())

            # 檢查是否包含所有必要的 scope
            required_scopes = {'openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/analytics.readonly'}
            if not required_scopes.issubset(returned_scopes):
                print(f"Scope 不匹配: 期望 {expected_scopes}, 收到 {returned_scopes}")
                # 不直接報錯，繼續處理，但記錄警告
                print("警告: OAuth scope 不完全匹配，但包含必要權限，繼續處理")

        # 獲取用戶信息
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        uri, headers, body = client.add_token(userinfo_endpoint)
        userinfo_response = requests.get(uri, headers=headers, data=body, timeout=30)

        if userinfo_response.status_code != 200:
            print(f"用戶信息請求失敗: {userinfo_response.status_code}")
            flash('獲取用戶信息失敗，請重新登入。', 'error')
            return redirect(url_for('index'))

        userinfo = userinfo_response.json()

        # 驗證用戶信息
        if not userinfo.get("email_verified"):
            flash("Google 帳戶郵箱未驗證，無法登入。", 'error')
            return redirect(url_for('index'))

        email = userinfo["email"]
        session['user_email'] = email

        # 清除 oauth_scopes session
        session.pop('oauth_scopes', None)

        # 檢查或建立用戶
        user = UserConfig.query.filter_by(google_email=email).first()
        if not user:
            # 新用戶註冊
            user = UserConfig(
                google_email=email,
                ga_account_name=userinfo.get("name", ""),
                timezone='Asia/Taipei',
                credits=FREE_SIGNUP_CREDITS
            )

            # 產生推薦碼
            get_or_create_referral_code(user)

            db.session.add(user)

            # 處理推薦碼
            referral_code = request.args.get('ref')
            if referral_code and referral_code != user.referral_code:
                # 檢查推薦碼是否有效
                referrer = UserConfig.query.filter_by(referral_code=referral_code).first()
                if referrer:
                    user.referred_by = referral_code
                    # 獎勵被推薦人
                    user.credits += RECOMMEND_CREDITS
                    log_credit_change(user, RECOMMEND_CREDITS, 'referral', f'被 {referrer.google_email} 推薦註冊')
                    # 獎勵推薦人
                    referrer.credits += REFERRAL_AWARD_CREDITS
                    referrer.referral_credits += REFERRAL_AWARD_CREDITS
                    log_credit_change(referrer, REFERRAL_AWARD_CREDITS, 'referral', f'推薦 {email} 註冊')
                    # 記錄推薦日誌
                    ref_log = ReferralLog(
                        referrer_code=referral_code,
                        referred_email=email,
                        credits_awarded=REFERRAL_AWARD_CREDITS
                    )
                    db.session.add(ref_log)

            try:
                db.session.commit()
                flash(f'歡迎加入！您已獲得 {user.credits} 點數。', 'success')
            except Exception as e:
                print(f"新用戶註冊錯誤: {e}")
                db.session.rollback()
                flash('註冊過程發生錯誤，請重新嘗試。', 'error')
                return redirect(url_for('index'))
        else:
            flash(f'歡迎回來，{email}！', 'success')

        # 加密並儲存 refresh token
        tokens = client.token
        if 'refresh_token' in tokens:
            encrypted_refresh_token = encrypt_token(tokens['refresh_token'])
            if encrypted_refresh_token:
                user.google_refresh_token_encrypted = encrypted_refresh_token
                try:
                    db.session.commit()
                except Exception as e:
                    print(f"儲存 refresh token 錯誤: {e}")

        return redirect(url_for('dashboard'))

    except Exception as e:
        print(f"Google callback 處理錯誤: {e}")
        traceback.print_exc()
        flash('登入過程發生錯誤，請重新嘗試。', 'error')
        return redirect(url_for('index'))

# Helper function to get the LINE callback URL dynamically
def get_line_callback_url():
    current_host = request.host
    if current_host.endswith('.repl.co'):
        return f"https://{current_host}/line-callback"
    elif current_host.endswith('.replit.app'):
        return f"https://{current_host}/line-callback"
    else:
        return 'https://galinereporter.replit.app/line-callback'

@app.route('/login/line')
def login_line():
    if not session.get('current_user_google_email'):
        flash("請先登入 Google 帳號，再連結 LINE。", "warning")
        return redirect(url_for('login_google'))

    # 檢查必要的 LINE 設定
    if not LINE_CHANNEL_ID or not LINE_CHANNEL_SECRET:
        flash("LINE 設定不完整，請聯繫管理員。", "error")
        return redirect(url_for('settings'))

    state = str(uuid.uuid4())
    session['line_oauth_state'] = state

    # 動態決定 LINE 重定向 URI
    redirect_uri = get_line_callback_url()

    if not redirect_uri:
        flash("無法決定 LINE callback URL，請聯繫管理員。", "error")
        return redirect(url_for('index'))
url_for('settings'))

    print(f"LINE OAuth - 使用重定向 URI: {redirect_uri}")

    # LINE OAuth 授權 URL
    params = {
        'response_type': 'code',
        'client_id': LINE_CHANNEL_ID,
        'redirect_uri': redirect_uri,
        'state': state,
        'scope': 'profile'
        }

    from urllib.parse import urlencode
    auth_url = 'https://access.line.me/oauth2/v2.1/authorize?' + urlencode(params)
    return redirect(auth_url)

@app.route('/line-callback')
def line_callback():
    code = request.args.get('code')
    error = request.args.get('error')
    state = request.args.get('state')

    if error:
        flash(f"LINE 登入失敗: {error}", "error")
        return redirect(url_for('settings'))

    if not code:
        flash("LINE 登入失敗：未收到授權碼", "error")
        return redirect(url_for('settings'))

    # 檢查 state 參數
    if state != session.get('line_oauth_state'):
        flash("LINE 登入失敗：狀態參數不匹配", "error")
        return redirect(url_for('settings'))

    # 檢查必要的 LINE 設定
    if not LINE_CHANNEL_ID or not LINE_CHANNEL_SECRET:
        flash("LINE 設定不完整，請聯繫管理員。", "error")
        return redirect(url_for('settings'))

    # 動態決定 LINE 重定向 URI（必須與授權時一致）
    redirect_uri = get_line_callback_url()

    if not redirect_uri:
        flash("無法決定 LINE callback URL，請聯繫管理員。", "error")
        return redirect(url_for('settings'))

    print(f"LINE Token Exchange - 使用重定向 URI: {redirect_uri}")

    # 交換 access token
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'client_id': LINE_CHANNEL_ID,
        'client_secret': LINE_CHANNEL_SECRET
    }

    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    try:
        token_response = requests.post('https://api.line.me/oauth2/v2.1/token', data=token_data, headers=headers)

        if token_response.status_code != 200:
            print(f"LINE Token 交換失敗: Status {token_response.status_code}, Response: {token_response.text}")
            flash(f"LINE Token 交換失敗: {token_response.status_code}", "error")
            return redirect(url_for('settings'))

        token_info = token_response.json()
        access_token = token_info.get('access_token')

        if not access_token:
            flash("LINE Token 交換失敗：未收到 access token", "error")
            return redirect(url_for('settings'))

        # 取得使用者資訊
        profile_headers = {'Authorization': f'Bearer {access_token}'}
        profile_response = requests.get('https://api.line.me/v2/profile', headers=profile_headers)

        if profile_response.status_code != 200:
            print(f"取得 LINE 使用者資訊失敗: Status {profile_response.status_code}, Response: {profile_response.text}")
            flash(f"取得 LINE 使用者資訊失敗: {profile_response.status_code}", "error")
            return redirect(url_for('settings'))

        profile_info = profile_response.json()
        line_user_id = profile_info.get('userId')

        if not line_user_id:
            flash("取得 LINE 使用者 ID 失敗", "error")
            return redirect(url_for('settings'))

        # 更新資料庫
        google_email = session.get('current_user_google_email')
        if google_email:
            with app.app_context():
                user_config = UserConfig.query.filter_by(google_email=google_email).first()
                if user_config:
                    user_config.line_user_id = line_user_id
                    db.session.commit()
                    flash("LINE 帳號連結成功！", "success")
                    print(f"LINE 帳號連結成功：{google_email} -> {line_user_id}")
                else:
                    flash("找不到對應的使用者設定", "error")
        else:
            flash("請先登入 Google 帳號", "warning")

    except requests.exceptions.RequestException as e:
        print(f"LINE API 請求錯誤: {e}")
        flash("LINE 連結過程中發生網路錯誤", "error")
    except Exception as e:
        print(f"LINE 連結未知錯誤: {e}")
        flash("LINE 連結失敗，請稍後再試", "error")

    return redirect(url_for('settings'))

@app.route('/set-ga-property', methods=['POST'])
def set_ga_property():
    current_user_email = session.get('current_user_google_email')
    if not current_user_email: flash("請先登入 Google。", "error"); return redirect(url_for('settings'))
    selected_property_id = request.form.get('property_id')
    if not selected_property_id or not selected_property_id.isdigit(): flash("選擇的 Property ID 格式錯誤。", "error"); return redirect(url_for('settings'))
    _ , error_msg, detailed_properties_list = get_ga_properties_from_db(user_email=current_user_email)
    if error_msg: flash(f"設定 GA 資源時無法重新獲取資源清單: {error_msg}", "error"); return redirect(url_for('settings'))
    selected_prop_details = None
    for prop_detail in detailed_properties_list:
        if prop_detail.get('id') == selected_property_id: selected_prop_details = prop_detail; break
    with app.app_context():
        config = UserConfig.query.filter_by(google_email=current_user_email).first()
        if config is None: flash(f"找不到 {current_user_email} 的設定記錄。", "error"); return redirect(url_for('settings'))
        config.ga_property_id = selected_property_id
        if selected_prop_details: config.ga_account_name = selected_prop_details.get('account_name_raw'); config.ga_property_name = selected_prop_details.get('property_name_raw')
        else: config.ga_account_name = None; config.ga_property_name = None; print(f"警告：為 {current_user_email} 設定 Property ID {selected_property_id} 時，無法找到詳細名稱。")
        config.updated_at = datetime.datetime.utcnow(); db.session.commit()
        display_name = selected_prop_details.get('property_name_raw', selected_property_id) if selected_prop_details else selected_property_id
        print(f"為 {current_user_email} 儲存 GA Property ID: {selected_property_id} (Name: {display_name})"); flash(f"成功設定 GA4 資源為: {display_name}", "success")
    return redirect(url_for('settings'))

@app.route('/run-report-job', methods=['POST'])
def run_report_job():
    auth_header = request.headers.get('Authorization'); expected_token = f"Bearer {SCHEDULER_SECRET_TOKEN}" if SCHEDULER_SECRET_TOKEN else None
    if not expected_token or not auth_header or auth_header != expected_token: return jsonify({"status": "error", "message": "Unauthorized"}), 401
    data = request.get_json(); date_mode = data.get('date_mode') if data else None
    if not date_mode or date_mode not in ['yesterday', 'today']: return jsonify({"status": "error", "message": "Invalid or missing 'date_mode'"}), 400
    print(f"收到排程器請求，準備為所有活躍使用者執行報表 (Mode: {date_mode})...")
    error_count = 0; success_count = 0
    with app.app_context():
        active_configs = UserConfig.query.filter_by(is_active=True).all()
        if not active_configs: print("沒有活躍的使用者設定需要處理。"); return jsonify({"status": "no_active_users", "message": "No active configurations to process."}), 200
        for config_entry in active_configs:
            print(f"正在為 UserConfig ID: {config_entry.id} (Email: {config_entry.google_email}) 執行報表...")
            try: run_and_send_report(user_config_id=config_entry.id, date_mode=date_mode); success_count +=1
            except Exception as e: error_count += 1; print(f"為 UserConfig ID: {config_entry.id} 執行報表時發生頂層錯誤: {e}\n{traceback.format_exc()}")
    message = f"Scheduled job finished. Success: {success_count}, Errors: {error_count}."
    print(message); status_code = 500 if error_count > 0 and success_count == 0 else 200
    return jsonify({"status": "completed", "message": message, "success_count": success_count, "error_count": error_count}), status_code

@app.route('/admin')
@admin_login_required
def admin_dashboard():
    try:
        with app.app_context(): all_user_configs = UserConfig.query.order_by(UserConfig.updated_at.desc()).all()
        return render_template('admin_dashboard.html', user_configs=all_user_configs)
    except Exception as e: print(f"載入管理員儀表板時發生錯誤: {e}"); traceback.print_exc(); flash("載入管理介面時發生內部錯誤。", "error"); return "載入管理介面時發生內部錯誤。", 500

@app.cli.command("set-admin")
@click.argument("email")
def set_admin_command(email):
    with app.app_context():
        user_config = UserConfig.query.filter_by(google_email=email).first()
        if user_config:
            if not user_config.is_admin: user_config.is_admin = True; db.session.commit(); print(f"已成功將 {email} 設為管理員。")
            else: print(f"{email} 已經是管理員了。")
        else: new_admin_config = UserConfig(google_email=email, is_admin=True, timezone='Asia/Taipei', is_active=False); db.session.add(new_admin_config); db.session.commit(); print(f"已為 {email} 建立新的設定記錄並設為管理員。請該使用者登入以完善其他設定並啟用服務。")

@app.route('/test-google-token')
def test_google_token():
    current_user_email = session.get('current_user_google_email')
    result_message = ""
    if not current_user_email: flash("請先登入 Google。", "error"); session['google_access_token_test_result'] = "錯誤：未登入 Google。"; return redirect(url_for('index'))
    access_token = get_google_access_token(user_email=current_user_email)
    if access_token: result_message = f"成功為 {current_user_email} 取得 Access Token: {access_token[:10]}..." ; print(result_message)
    else: result_message = f"為 {current_user_email} 取得 Access Token 失敗。"
    session['google_access_token_test_result'] = result_message; return redirect(url_for('index'))

@app.route('/logout-all-debug')
def logout_all_debug():
    current_user_email = session.get('current_user_google_email')
    if current_user_email:
        with app.app_context():
            config = UserConfig.query.filter_by(google_email=current_user_email).first()
            if config: config.google_refresh_token_encrypted = None; config.ga_property_id = None; config.ga_account_name = None; config.ga_property_name = None; config.updated_at = datetime.datetime.utcnow(); db.session.commit(); print(f"DEBUG: Cleared Google token and GA info for {current_user_email}."); flash(f"已清除 {current_user_email} 的 Google 連結及 GA 資源設定。", "info")
            else: flash("找不到目前使用者的設定可清除。", "info")
    else: flash("請先登入 Google。", "warning")
    session.clear(); flash("已登出。", "info")
    return redirect(url_for('index'))

@app.route('/test-ga-report-manual/<date_mode>')
def test_ga_report_manual(date_mode):
    current_user_email = session.get('current_user_google_email')
    if not current_user_email: flash("請先登入 Google。", "error"); return redirect(url_for('index'))
    if date_mode not in ['yesterday', 'today']: flash("無效的日期模式。", "error"); return redirect(url_for('index'))
    with app.app_context(): config = UserConfig.query.filter_by(google_email=current_user_email).first()
    if not config: flash(f"找不到 {current_user_email} 的設定。", "error"); return redirect(url_for('index'))
    print(f"手動觸發 {current_user_email} 的報表任務 (Mode: {date_mode})...")
    run_and_send_report(user_config_id=config.id, date_mode=date_mode)
    session['ga_report_test_result'] = f"為 {current_user_email} 手動觸發 ({date_mode}) 完成，詳見 Log 或 LINE。"
    return redirect(url_for('index'))

@app.route('/toggle-schedule', methods=['POST'])
def toggle_schedule():
    current_user_email = session.get('current_user_google_email')
    if not current_user_email: return jsonify({"status": "error", "message": "請先登入 Google。"}), 401
    action = request.form.get('is_active_toggle')
    with app.app_context():
        config = UserConfig.query.filter_by(google_email=current_user_email).first()
        if config is None: return jsonify({"status": "error", "message": f"找不到使用者 {current_user_email} 的設定記錄。"}), 404
        new_status = False
        if action == 'enable': config.is_active = True; new_status = True
        elif action == 'disable': config.is_active = False; new_status = False
        else: return jsonify({"status": "error", "message": "無效的操作。"}), 400
        db.session.commit(); status_text = "啟用" if new_status else "停用"; print(f"使用者 {current_user_email} 已{status_text}自動排程。")
        return jsonify({"status": "success", "message": f"自動排程已{status_text}！", "is_active": new_status}), 200
# 在 app.py 中
@app.route('/privacy')
def privacy_policy(): # <--- 確保函式名稱是 privacy_policy
    today_date = datetime.date.today().strftime('%Y-%m-%d')
    current_year = datetime.date.today().year
    return render_template('privacy_policy.html', current_date=today_date, current_year=current_year)

@app.route('/terms')
def terms_of_service(): # <--- 確保函式名稱是 terms_of_service
    effective_date = datetime.date.today().strftime('%Y-%m-%d') # 或者一個固定的日期
    current_year = datetime.date.today().year
    return render_template('terms_of_service.html', effective_date=effective_date, current_year=current_year)

# --- Google OAuth 認證路由 ---
@app.route('/login/google')
def login_google():
    """Google OAuth 登入"""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash('Google OAuth 未設定，請聯繫管理員。', 'error')
        return redirect(url_for('index'))

    # 建立 OAuth flow
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/o/oauth2/token",
                "redirect_uris": [url_for('google_callback', _external=True)]
            }
        },
        scopes=['openid', 'email', 'profile', 'https://www.googleapis.com/auth/analytics.readonly']
    )

    # 設定 redirect URI
    flow.redirect_uri = 'https://galinereporter-1-backtrue.replit.app/google-callback'

    # 獲取授權 URL
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )

    # 將 state 存入 session
    session['state'] = state

    return redirect(authorization_url)

@app.route('/google-callback')
def google_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')

    if error:
        flash(f'Google 授權失敗: {error}', 'error')
        return redirect(url_for('index'))

    if not code:
        flash('Google 登入失敗：缺少授權碼', 'error')
        return redirect(url_for('index'))

    try:
        # 準備憑證設定
        client_config = {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/o/oauth2/token",
                "redirect_uris": [url_for('google_callback', _external=True)]
            }
        }

        # 建立 Flow 物件來處理 OAuth
        from google_auth_oauthlib.flow import Flow
        GOOGLE_SCOPES = ['openid', 'email', 'profile', 'https://www.googleapis.com/auth/analytics.readonly']
        flow = Flow.from_client_config(
            client_config,
            scopes=GOOGLE_SCOPES
        )
        flow.redirect_uri = 'https://galinereporter-1-backtrue.replit.app/google-callback'

        # 使用授權碼換取 tokens
        flow.fetch_token(authorization_response=request.url)

        # 取得憑證
        credentials = flow.credentials

        # 使用憑證取得使用者資訊
        from googleapiclient.discovery import build
        oauth2_service = build('oauth2', 'v2', credentials=credentials)
        user_info = oauth2_service.userinfo().get().execute()

        user_email = user_info.get('email')
        if not user_email:
            flash('無法取得 Google 帳號的 email 資訊', 'error')
            return redirect(url_for('index'))

        # 檢查或建立使用者紀錄
        user = UserConfig.query.filter_by(google_email=user_email).first()
        if not user:
            # 新使用者，建立紀錄
            user = UserConfig(google_email=user_email)
            db.session.add(user)

        # 更新 refresh token (加密後儲存)
        if credentials.refresh_token:
            encrypted_refresh_token = encrypt_token(credentials.refresh_token)
            if encrypted_refresh_token:
                user.google_refresh_token_encrypted = encrypted_refresh_token

        db.session.commit()

        # 設定 session
        session['user_email'] = user_email
        session['logged_in'] = True

        flash(f'歡迎，{user_email}！Google 帳號連結成功。', 'success')
        return redirect(url_for('index'))

    except Exception as e:
        flash(f'Google 登入過程發生錯誤: {str(e)}', 'error')
        return redirect(url_for('index'))

# Duplicate route removed - keeping only one line_callback definition
    code = request.args.get('code')
    state = request.args.get('state')

    if not code:
        flash('LINE 登入失敗：缺少授權碼', 'error')
        return redirect(url_for('index'))

    # 檢查 session 中的 user email
    user_email = session.get('user_email')
    if not user_email:
        flash('請先完成 Google 登入', 'error')
        return redirect(url_for('index'))

    # 使用授權碼換取 access token
    token_url = 'https://api.line.me/oauth2/v2.1/token'
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': url_for('line_callback', _external=True),
        'client_id': LINE_CHANNEL_ID,
        'client_secret': LINE_CHANNEL_SECRET
    }

    try:
        token_response = requests.post(token_url, data=token_data)
        token_response.raise_for_status()
        token_info = token_response.json()
        access_token = token_info.get('access_token')

        if not access_token:
            flash('LINE 登入失敗：無法取得存取權杖', 'error')
            return redirect(url_for('index'))

        # 使用 access token 取得用戶資訊
        profile_url = 'https://api.line.me/v2/profile'
        headers = {'Authorization': f'Bearer {access_token}'}
        profile_response = requests.get(profile_url, headers=headers)
        profile_response.raise_for_status()
        profile_info = profile_response.json()

        line_user_id = profile_info.get('userId')
        if not line_user_id:
            flash('LINE 登入失敗：無法取得用戶 ID', 'error')
            return redirect(url_for('index'))

        # 更新用戶的 LINE user ID
        user = UserConfig.query.filter_by(google_email=user_email).first()
        if user:
            user.line_user_id = line_user_id
            db.session.commit()
            flash('LINE 帳號連結成功！', 'success')
        else:
            flash('找不到對應的用戶紀錄', 'error')

    except requests.RequestException as e:
        flash(f'LINE API 呼叫失敗: {str(e)}', 'error')
    except Exception as e:
        flash(f'LINE 登入過程發生錯誤: {str(e)}', 'error')

    return redirect(url_for('dashboard'))

# --- Google Analytics 報告生成 ---
def generate_ga_report(user_config):
    pass

# --- 執行 Flask App ---
if __name__ == '__main__':
    with app.app_context():
        print("檢查並建立資料庫表格...")
        db.create_all()
        print("資料庫表格檢查完畢。")
    print("啟動 Flask 應用程式...")
    # 在開發環境中強制使用 HTTPS 設定
    import os
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'  # 禁用不安全傳輸
    app.run(host='0.0.0.0', port=5000, debug=True)