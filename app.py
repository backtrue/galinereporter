# -*- coding: utf-8 -*-
import os
import uuid
import requests
import time
from flask import Flask, redirect, request, session, url_for, render_template, flash, jsonify, Response
from dotenv import load_dotenv
from functools import wraps

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

# --- 載入環境變數 ---
load_dotenv()

app = Flask(__name__)
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
    __tablename__ = 'user_configs'; id = db.Column(db.Integer, primary_key=True); google_email = db.Column(String(255), nullable=False, unique=True, index=True); google_refresh_token_encrypted = db.Column(Text, nullable=True); line_user_id = db.Column(String(100), nullable=True, unique=False); ga_property_id = db.Column(String(50), nullable=True);
    ga_account_name = db.Column(String(255), nullable=True); ga_property_name = db.Column(String(255), nullable=True); timezone = db.Column(String(50), nullable=False, default='Asia/Taipei');
    is_active = db.Column(Boolean, nullable=False, default=True); is_admin = db.Column(Boolean, nullable=False, default=False)
    updated_at = db.Column(DateTime, nullable=False, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    def __repr__(self): return f'<UserConfig Email:{self.google_email} Admin:{self.is_admin}>'

class ReportSnapshot(db.Model):
    __tablename__ = 'report_snapshots'; id = db.Column(db.Integer, primary_key=True); config_id = db.Column(db.Integer, db.ForeignKey('user_configs.id'), nullable=False); snapshot_datetime_utc = db.Column(DateTime, nullable=False, default=datetime.datetime.utcnow); report_for_date = db.Column(String(10), nullable=False); report_for_timeslot = db.Column(String(20), nullable=False); sessions = db.Column(db.Integer, nullable=True); total_revenue = db.Column(db.Float, nullable=True); created_at = db.Column(DateTime, nullable=False, default=datetime.datetime.utcnow); user_config = db.relationship('UserConfig', backref=db.backref('report_snapshots_backref', lazy='dynamic'))
    def __repr__(self): return f'<ReportSnapshot ID:{self.id} ForDate:{self.report_for_date} Slot:{self.report_for_timeslot}>'

# --- 在應用程式初始化時嘗試建立資料庫表格 ---
with app.app_context():
    print("應用程式啟動：檢查並建立資料庫表格..."); db.create_all(); print("應用程式啟動：資料庫表格檢查/建立完畢。")

# --- Google/LINE OAuth/Bot 設定 ---
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID'); GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET'); GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"; # 自動檢測環境來設定正確的重新導向 URI
if os.getenv('REPL_OWNER') and os.getenv('REPL_SLUG'):
    # Preview 模式
    preview_url = f"https://{os.getenv('REPL_SLUG')}--{os.getenv('REPL_OWNER')}.repl.co"
    default_redirect_uri = f"{preview_url}/google-callback"
else:
    # Production 模式
    default_redirect_uri = 'https://galinereporter.replit.app/google-callback'

GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', default_redirect_uri); GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"
LINE_CHANNEL_ID = os.getenv('LINE_CHANNEL_ID'); LINE_CHANNEL_SECRET = os.getenv('LINE_CHANNEL_SECRET'); LINE_REDIRECT_URI = os.getenv('LINE_REDIRECT_URI', 'http://127.0.0.1:5000/line-callback')
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
                total_hist_sessions = sum(s.sessions for s in historical_snapshots if s.sessions is not None); total_hist_revenue = sum(s.total_revenue for s in historical_snapshots if s.total_revenue is not None); count_hist_days = len(historical_snapshots)
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
                           ga_report_test_result=report_result,
                           google_user_email_debug=current_user_email,
                           google_access_token_test_result=access_token_result)

# ... (其他所有路由 @app.route('/settings') 到 @app.route('/test-ga-report-manual/<date_mode>') 與上一版相同，此處省略) ...
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

@app.route('/login/google')
def login_google():
    session.pop('current_user_google_email', None); session.pop('ga_detailed_properties', None)
    try: google_config = requests.get(GOOGLE_DISCOVERY_URL).json(); authorization_endpoint = google_config['authorization_endpoint']
    except requests.exceptions.RequestException as e: flash(f"無法取得 Google OpenID 設定: {e}", "error"); return redirect(url_for('index'))
    state = str(uuid.uuid4()); session['google_oauth_state'] = state
    scope = "openid%20email%20profile%20https://www.googleapis.com/auth/analytics.readonly"; request_uri = f"{authorization_endpoint}?response_type=code&client_id={GOOGLE_CLIENT_ID}&redirect_uri={GOOGLE_REDIRECT_URI}&scope={scope}&state={state}&access_type=offline&prompt=consent"
    return redirect(request_uri)

@app.route('/google-callback')
def google_callback():
    code = request.args.get('code'); state = request.args.get('state'); stored_state = session.pop('google_oauth_state', None)
    if state is None or state != stored_state: flash('State parameter mismatch', 'error'); return redirect(url_for('settings'))
    if not code: flash('Missing authorization code', 'error'); return redirect(url_for('settings'))
    token_endpoint = None; userinfo_endpoint = None
    try: google_config = requests.get(GOOGLE_DISCOVERY_URL).json(); token_endpoint = google_config['token_endpoint']; userinfo_endpoint = google_config.get('userinfo_endpoint')
    except requests.exceptions.RequestException as e: flash(f"無法取得 Google OpenID 設定 (callback): {e}", "error"); return redirect(url_for('settings'))
    token_payload = {'code': code, 'client_id': GOOGLE_CLIENT_ID, 'client_secret': GOOGLE_CLIENT_SECRET, 'redirect_uri': GOOGLE_REDIRECT_URI, 'grant_type': 'authorization_code'}
    token_response = None
    try:
        token_response = requests.post(token_endpoint, data=token_payload); token_response.raise_for_status()
        token_json = token_response.json(); refresh_token = token_json.get('refresh_token'); access_token = token_json.get('access_token')
        user_email = None
        if access_token and userinfo_endpoint:
            try: headers = {'Authorization': f'Bearer {access_token}'}; userinfo_res = requests.get(userinfo_endpoint, headers=headers); userinfo_res.raise_for_status(); userinfo = userinfo_res.json(); user_email = userinfo.get('email')
            except Exception as e_userinfo: print(f"DEBUG: 無法取得 Google UserInfo: {e_userinfo}"); flash("無法驗證 Google 帳號資訊。", "error"); return redirect(url_for('settings'))
        if not user_email: flash("無法從 Google 取得 Email，無法完成綁定。", "error"); return redirect(url_for('settings'))
        session['current_user_google_email'] = user_email
        if refresh_token:
            with app.app_context():
                config = UserConfig.query.filter_by(google_email=user_email).first()
                if config is None: config = UserConfig(google_email=user_email, timezone='Asia/Taipei'); db.session.add(config)
                else: config.timezone = 'Asia/Taipei'
                encrypted_token = encrypt_token(refresh_token)
                if encrypted_token: config.google_refresh_token_encrypted = encrypted_token; config.ga_property_id = None; config.ga_account_name=None; config.ga_property_name=None; config.updated_at = datetime.datetime.utcnow(); db.session.commit(); print(f"為 {user_email} 儲存 Google Refresh Token。"); flash("成功連結 Google 帳號！請接著設定 GA 資源。", "success")
                else: print(f"加密 {user_email} 的 Refresh Token 失敗。"); flash("儲存憑證加密錯誤。", "error")
        else:
             with app.app_context(): config = UserConfig.query.filter_by(google_email=user_email).first()
             if config and config.google_refresh_token_encrypted: print(f"{user_email} 未取得新 Refresh Token (可能已存在)。"); flash("重新驗證 Google 帳號成功！", "info")
             elif config: config.google_refresh_token_encrypted = None; db.session.commit(); print(f"錯誤：{user_email} 未取得 Refresh Token 且DB中無有效Token。"); flash("無法取得 Google Refresh Token，請重試。", "error")
             else: print(f"錯誤：{user_email} 為新用戶但未取得 Refresh Token。"); flash("無法取得 Google Refresh Token，請確保同意所有權限。", "error")
        return redirect(url_for('settings'))
    except requests.exceptions.RequestException as e: print(f"交換 Google Code 失敗: {e}"); flash("與 Google 交換憑證錯誤。", "error"); return redirect(url_for('settings'))
    except Exception as e: print(f"處理 Google Callback 未知錯誤: {e}\n{traceback.format_exc()}"); flash("處理 Google 回應未知錯誤。", "error"); return redirect(url_for('settings'))

@app.route('/login/line')
def login_line():
    current_user_email = session.get('current_user_google_email')
    if not current_user_email: flash("請先登入 Google 帳號，才能綁定 LINE。", "warning"); return redirect(url_for('index'))
    state = str(uuid.uuid4()); session['line_oauth_state'] = state; session['line_auth_target_google_email'] = current_user_email
    line_login_url = f"https://access.line.me/oauth2/v2.1/authorize?response_type=code&client_id={LINE_CHANNEL_ID}&redirect_uri={LINE_REDIRECT_URI}&state={state}&scope=profile%20openid%20email"
    return redirect(line_login_url)

@app.route('/line-callback')
def line_callback():
    target_google_email = session.pop('line_auth_target_google_email', None)
    code = request.args.get('code'); state_from_line = request.args.get('state'); stored_state = session.pop('line_oauth_state', None)
    if state_from_line is None or state_from_line != stored_state: flash('LINE 登入 state 參數不符或已過期，請重試。', 'error'); return redirect(url_for('settings'))
    if not code: flash('LINE 登入未返回授權碼，請重試。', 'error'); return redirect(url_for('settings'))
    if not target_google_email: flash('無法確定要為哪個 Google 帳號綁定 LINE，請重新登入 Google。', 'error'); return redirect(url_for('index'))
    token_url = "https://api.line.me/oauth2/v2.1/token"; headers = {'Content-Type': 'application/x-www-form-urlencoded'}; data = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': LINE_REDIRECT_URI, 'client_id': LINE_CHANNEL_ID, 'client_secret': LINE_CHANNEL_SECRET}
    token_response = None; profile_response = None
    try:
        token_response = requests.post(token_url, headers=headers, data=data); token_response.raise_for_status()
        token_data = token_response.json(); line_access_token = token_data.get('access_token')
        if not line_access_token: print(f"無法從 LINE 取得 Access Token for {target_google_email}"); flash("無法取得 LINE Access Token", "error"); return redirect(url_for('settings'))
        profile_url = "https://api.line.me/v2/profile"; profile_headers = {'Authorization': f'Bearer {line_access_token}'}
        profile_response = requests.get(profile_url, headers=profile_headers); profile_response.raise_for_status()
        profile_data = profile_response.json(); user_id_from_line = profile_data.get('userId')
        if user_id_from_line:
            with app.app_context():
                config = UserConfig.query.filter_by(google_email=target_google_email).first()
                if config is None: flash(f"找不到 Google 帳號 {target_google_email} 的設定記錄。", "error"); return redirect(url_for('settings'))
                config.line_user_id = user_id_from_line; config.updated_at = datetime.datetime.utcnow(); db.session.commit()
                print(f"為 {target_google_email} 儲存 LINE User ID: {user_id_from_line}"); flash(f"成功為 Google 帳號 {target_google_email} 連結 LINE 帳號！", "success")
        else: print(f"無法從 LINE Profile 取得 User ID for {target_google_email}"); flash("無法取得 LINE User ID", "error")
        return redirect(url_for('settings'))
    except requests.exceptions.RequestException as e: print(f"LINE API 請求失敗 for {target_google_email}: {e}"); flash("與 LINE API 連接錯誤。", "error"); return redirect(url_for('settings'))
    except Exception as e: print(f"處理 LINE Callback 時發生未知錯誤 for {target_google_email}: {e}"); flash("處理 LINE 回應時發生未知錯誤。", "error"); return redirect(url_for('settings'))

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
# --- 執行 Flask App ---
if __name__ == '__main__':
    with app.app_context():
        print("檢查並建立資料庫表格..."); db.create_all(); print("資料庫表格檢查完畢。")
    print("啟動 Flask 應用程式...")
    app.run(host='0.0.0.0', port=5000, debug=True)