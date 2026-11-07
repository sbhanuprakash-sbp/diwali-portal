import csv
import hmac
import io
import os
import re
import secrets
from collections import Counter
from datetime import datetime, timedelta, timezone
from functools import wraps

import json
import threading
import urllib.request

import bcrypt
import jwt
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, Response, g, jsonify, request  # noqa: E402
from flask_cors import CORS  # noqa: E402
from flask_limiter import Limiter  # noqa: E402
from flask_limiter.util import get_remote_address  # noqa: E402
from flask_sqlalchemy import SQLAlchemy  # noqa: E402
from werkzeug.middleware.proxy_fix import ProxyFix  # noqa: E402

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=int(os.getenv('TRUSTED_PROXIES', '1') or 1), x_proto=1, x_host=1)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024

# ---- configuration -------------------------------------------------------
SECRET = os.getenv('JWT_SECRET', '')
if len(SECRET) < 32 or SECRET.startswith('replace-with'):
    raise RuntimeError('Set JWT_SECRET to a random string of at least 32 characters '
                       '(python -c "import secrets; print(secrets.token_urlsafe(48))").')
app.config['SECRET_KEY'] = SECRET

ORIGINS = [o.strip().rstrip('/') for o in os.getenv('FRONTEND_ORIGIN', 'http://127.0.0.1:5500').split(',') if o.strip()]
CORS(app, origins=ORIGINS, supports_credentials=False, allow_headers=['Content-Type', 'Authorization'])

raw_db = os.getenv('DATABASE_URL', 'sqlite:///diwali_dev.db')
# psycopg v3 needs an explicit driver name in the SQLAlchemy URL
if raw_db.startswith('postgres://'):
    raw_db = 'postgresql+psycopg://' + raw_db[len('postgres://'):]
elif raw_db.startswith('postgresql://'):
    raw_db = 'postgresql+psycopg://' + raw_db[len('postgresql://'):]
app.config['SQLALCHEMY_DATABASE_URI'] = raw_db
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_pre_ping': True}
db = SQLAlchemy(app)

limiter = Limiter(get_remote_address, app=app, default_limits=['300 per hour'], storage_uri='memory://')

USERNAME_RE = re.compile(r'^[a-z0-9_.-]{3,40}$')
DUMMY_HASH = bcrypt.hashpw(b'dummy-password', bcrypt.gensalt())  # equalises timing for unknown users


def now_utc():
    return datetime.now(timezone.utc)


def iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def pw_bytes(p):
    return p.encode('utf-8')[:72]  # bcrypt only uses the first 72 bytes


def hash_pw(p):
    return bcrypt.hashpw(pw_bytes(p), bcrypt.gensalt())


def check_pw(p, h):
    try:
        return bcrypt.checkpw(pw_bytes(p), h)
    except Exception:
        return False


def valid_password(p):
    return 10 <= len(p) and len(p.encode('utf-8')) <= 72


def clean_photo(url):
    url = str(url or '').strip()[:500]
    return url if (not url or url.startswith('https://')) else None


# ---- models --------------------------------------------------------------
class Recipient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    display_name = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(40), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.LargeBinary, nullable=False)
    relation_label = db.Column(db.String(50), nullable=True)
    greeting = db.Column(db.Text, nullable=False, default='Happy Diwali! 🪔')
    photo_url = db.Column(db.String(500), nullable=True)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now_utc)


class Visit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    relation = db.Column(db.String(80), nullable=False)
    visitor_message = db.Column(db.Text, nullable=False)
    user_agent = db.Column(db.String(500))
    screen_size = db.Column(db.String(40))
    ip_address = db.Column(db.String(64))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now_utc)


class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    visit_id = db.Column(db.Integer, db.ForeignKey('visit.id'), nullable=True)
    username_attempted = db.Column(db.String(60), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('recipient.id'), nullable=True)
    user_agent = db.Column(db.String(500))
    ip_address = db.Column(db.String(64))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now_utc)


class LoginSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('recipient.id'), nullable=False)
    visit_id = db.Column(db.Integer, db.ForeignKey('visit.id'), nullable=True)
    started_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now_utc)
    last_seen_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now_utc)
    ended_at = db.Column(db.DateTime(timezone=True), nullable=True)
    active = db.Column(db.Boolean, nullable=False, default=True)


class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('recipient.id'), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey('login_session.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now_utc)


class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event = db.Column(db.String(60), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('recipient.id'), nullable=True)
    visit_id = db.Column(db.Integer, db.ForeignKey('visit.id'), nullable=True)
    detail = db.Column(db.String(300))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now_utc)


def log_activity(event, recipient_id=None, visit_id=None, detail=None):
    db.session.add(Activity(event=event, recipient_id=recipient_id, visit_id=visit_id,
                            detail=(detail or '')[:300] or None))


def end_sessions(recipient_id):
    for s in LoginSession.query.filter_by(recipient_id=recipient_id, active=True).all():
        s.active = False
        s.ended_at = now_utc()


# ---- auth ----------------------------------------------------------------
def make_token(subject, role, token_id=None):
    payload = {'sub': str(subject), 'role': role, 'iat': now_utc(), 'exp': now_utc() + timedelta(hours=12)}
    if token_id:
        payload['jti'] = token_id
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')


def require_auth(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            header = request.headers.get('Authorization', '')
            if not header.startswith('Bearer '):
                return jsonify(error='Authentication required'), 401
            try:
                payload = jwt.decode(header[7:], app.config['SECRET_KEY'], algorithms=['HS256'])
            except jwt.PyJWTError:
                return jsonify(error='Invalid or expired session'), 401
            if role and payload.get('role') != role:
                return jsonify(error='Not authorized'), 403
            if payload.get('role') == 'visitor':
                session = LoginSession.query.filter_by(token_id=payload.get('jti'), active=True).first()
                if not session or session.ended_at:
                    return jsonify(error='Session ended; please log in again'), 401
                rec = db.session.get(Recipient, session.recipient_id)
                if not rec or not rec.active:
                    session.active = False
                    session.ended_at = now_utc()
                    db.session.commit()
                    return jsonify(error='This account has been disabled.'), 401
                session.last_seen_at = now_utc()
                db.session.commit()
                g.login_session = session
                g.recipient_id = session.recipient_id
            else:
                g.admin_id = payload.get('sub')
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def body_json():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


@app.after_request
def secure_headers(resp):
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    return resp


@app.errorhandler(429)
def too_many(_e):
    return jsonify(error='Too many attempts. Please wait a few minutes and try again.'), 429


@app.errorhandler(413)
def too_big(_e):
    return jsonify(error='That request is too large.'), 413


# ---- device parsing (ordinary User-Agent header only) -----------------------
def parse_ua(ua):
    ua = ua or ''
    l = ua.lower()
    if not ua:
        device = 'Unknown'
    elif 'ipad' in l or 'tablet' in l or ('android' in l and 'mobile' not in l):
        device = 'Tablet'
    elif 'mobi' in l or 'iphone' in l or 'android' in l:
        device = 'Mobile'
    else:
        device = 'Desktop'
    os_name = 'Unknown'
    for key, name in [('windows', 'Windows'), ('iphone', 'iOS'), ('ipad', 'iPadOS'), ('android', 'Android'),
                      ('mac os x', 'macOS'), ('cros', 'ChromeOS'), ('linux', 'Linux')]:
        if key in l:
            os_name = name
            break
    browser = 'Unknown'
    for key, name in [('edg/', 'Edge'), ('edga/', 'Edge'), ('opr/', 'Opera'), ('samsungbrowser', 'Samsung Internet'),
                      ('firefox/', 'Firefox'), ('fxios', 'Firefox'), ('crios', 'Chrome'), ('chrome/', 'Chrome'),
                      ('safari/', 'Safari')]:
        if key in l:
            browser = name
            break
    return {'device': device, 'os': os_name, 'browser': browser}


# ---- public API ------------------------------------------------------------
@app.get('/')
def index():
    return jsonify(status='ok', service='diwali-portal-api')


@app.get('/api/health')
def health():
    return jsonify(status='ok', service='diwali-portal-api')


@app.post('/api/visits')
@limiter.limit('20 per hour')
def create_visit():
    data = body_json()
    relation = str(data.get('relation', '')).strip()[:80]
    message = str(data.get('message', '')).strip()[:1500]  # optional; the visitor page no longer asks for one
    if not relation:
        return jsonify(error='Choose a relationship or enter your own.'), 400
    visit = Visit(relation=relation, visitor_message=message,
                  user_agent=request.headers.get('User-Agent', '')[:500],
                  screen_size=str(data.get('screen_size', ''))[:40], ip_address=request.remote_addr)
    db.session.add(visit)
    db.session.flush()
    log_activity('visitor_message_submitted', visit_id=visit.id, detail=relation)
    db.session.commit()
    return jsonify(visit_id=visit.id, message='Your entry has been recorded. Continue to login.'), 201


def too_many_failures(username):
    since = now_utc() - timedelta(minutes=15)
    n = LoginAttempt.query.filter(LoginAttempt.username_attempted == username,
                                  LoginAttempt.success.is_(False), LoginAttempt.created_at >= since).count()
    return n >= 8


@app.post('/api/login')
@limiter.limit('10 per minute; 60 per hour')
def visitor_login():
    data = body_json()
    username = str(data.get('username', '')).strip().lower()[:40]
    password = str(data.get('password', ''))
    visit_id = data.get('visit_id')
    visit_id = visit_id if isinstance(visit_id, int) and not isinstance(visit_id, bool) else None
    visit = db.session.get(Visit, visit_id) if visit_id else None
    recipient = Recipient.query.filter_by(username=username, active=True).first() if username else None
    if recipient and too_many_failures(recipient.username):
        return jsonify(error='Too many failed attempts for this account. Try again in 15 minutes.'), 429
    pw_ok = check_pw(password, recipient.password_hash if recipient else DUMMY_HASH)
    valid = bool(visit and recipient and pw_ok)
    # Unknown usernames are stored masked so a password typed into the wrong box is never logged in full.
    if recipient:
        label = recipient.username
    elif not username:
        label = '(empty)'
    else:
        label = f'{username[:2]}… ({len(username)} chars)'
    db.session.add(LoginAttempt(visit_id=visit_id, username_attempted=label, success=valid,
                                recipient_id=recipient.id if valid else None,
                                user_agent=request.headers.get('User-Agent', '')[:500], ip_address=request.remote_addr))
    log_activity('login_success' if valid else 'login_failed', recipient_id=recipient.id if valid else None,
                 visit_id=visit_id, detail=label)
    if not valid:
        db.session.commit()
        return jsonify(error='Name or secret is incorrect.'), 401
    token_id = secrets.token_urlsafe(24)
    session = LoginSession(token_id=token_id, recipient_id=recipient.id, visit_id=visit_id)
    db.session.add(session)
    db.session.flush()
    token = make_token(recipient.id, 'visitor', token_id)
    db.session.commit()
    return jsonify(token=token, display_name=recipient.display_name, greeting=recipient.greeting,
                   photo_url=recipient.photo_url, session_id=session.id)

def forward_to_formspree(name, username, relation, message):
    url = os.getenv('FORMSPREE_URL', '')
    if not url.startswith('https://formspree.io/'):
        return
    payload = json.dumps({'_subject': f'Diwali reply from {name}', 'name': name,
                          'username': username, 'relationship': relation,
                          'message': message}).encode()

    def send():
        try:
            req = urllib.request.Request(url, data=payload, method='POST',
                                         headers={'Content-Type': 'application/json',
                                                  'Accept': 'application/json'})
            urllib.request.urlopen(req, timeout=10).read()
        except Exception as e:
            app.logger.warning('Formspree forward failed: %s', e)

    threading.Thread(target=send, daemon=True).start()

@app.post('/api/replies')
@limiter.limit('20 per hour')
@require_auth('visitor')
def submit_reply():
    message = str(body_json().get('message', '')).strip()
    if not message:
        return jsonify(error='Write a reply before sending.'), 400
    if len(message) > 1000:
        return jsonify(error='Reply is too long (maximum 1000 characters).'), 400
    db.session.add(Reply(recipient_id=g.recipient_id, session_id=g.login_session.id, message=message))
    log_activity('reply_submitted', recipient_id=g.recipient_id, visit_id=g.login_session.visit_id)
    db.session.commit()
    rec = db.session.get(Recipient, g.recipient_id)
    visit = db.session.get(Visit, g.login_session.visit_id) if g.login_session.visit_id else None
    forward_to_formspree(rec.display_name, rec.username, visit.relation if visit else '', message)
    return jsonify(message='Your reply has been saved. Thank you!'), 201


@app.post('/api/credentials')
@limiter.limit('10 per hour')
@require_auth('visitor')
def change_credentials():
    data = body_json()
    username = str(data.get('username', '')).strip().lower()
    password = str(data.get('password', ''))
    recipient = db.session.get(Recipient, g.recipient_id)
    if not check_pw(str(data.get('current_password', '')), recipient.password_hash):
        return jsonify(error='Your current secret is incorrect.'), 403
    if not USERNAME_RE.match(username):
        return jsonify(error='Name: 3–40 characters, only letters, numbers, . _ - (no spaces).'), 400
    if not valid_password(password):
        return jsonify(error='Use a secret with 10–72 characters.'), 400
    if Recipient.query.filter(Recipient.username == username, Recipient.id != recipient.id).first():
        return jsonify(error='That name is already taken.'), 409
    recipient.username = username
    recipient.password_hash = hash_pw(password)
    log_activity('credentials_changed', recipient_id=recipient.id)
    db.session.commit()
    return jsonify(message='Your login details have been updated.')


@app.post('/api/logout')
@require_auth('visitor')
def logout():
    s = g.login_session
    s.active = False
    s.ended_at = now_utc()
    log_activity('logout', recipient_id=g.recipient_id, visit_id=s.visit_id)
    db.session.commit()
    return jsonify(message='Logged out.')


# ---- admin -----------------------------------------------------------------
@app.post('/api/admin/login')
@limiter.limit('5 per minute; 20 per hour')
def admin_login():
    data = body_json()
    username = os.getenv('ADMIN_USERNAME', '')
    password_hash = os.getenv('ADMIN_PASSWORD_HASH', '')
    if not username or not password_hash:
        return jsonify(error='Admin account is not configured on the server.'), 503
    user_ok = hmac.compare_digest(str(data.get('username', '')).encode(), username.encode())
    try:
        pass_ok = bcrypt.checkpw(pw_bytes(str(data.get('password', ''))), password_hash.encode())
    except Exception:
        pass_ok = False
    if not (user_ok and pass_ok):
        log_activity('admin_login_failed', detail=request.remote_addr)
        db.session.commit()
        return jsonify(error='Invalid administrator credentials.'), 401
    log_activity('admin_login', detail=request.remote_addr)
    db.session.commit()
    return jsonify(token=make_token('admin', 'admin'))


@app.get('/api/admin/overview')
@require_auth('admin')
def admin_overview():
    return jsonify(
        visits=Visit.query.count(),
        unique_ips=db.session.query(Visit.ip_address).distinct().count(),
        login_sessions=LoginSession.query.count(),
        active_sessions=LoginSession.query.filter_by(active=True).count(),
        successful_logins=LoginAttempt.query.filter_by(success=True).count(),
        failed_logins=LoginAttempt.query.filter_by(success=False).count(),
        replies=Reply.query.count(),
        recipients=Recipient.query.count())


def parse_day(s):
    try:
        return datetime.strptime(str(s), '%Y-%m-%d').replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def in_range(q, col):
    f, t = parse_day(request.args.get('date_from')), parse_day(request.args.get('date_to'))
    if f:
        q = q.filter(col >= f)
    if t:
        q = q.filter(col < t + timedelta(days=1))
    return q


def build_rows(kind):
    """Return (columns, rows) for a dashboard table; shared by JSON and CSV export."""
    rec = {r.id: r for r in Recipient.query.all()}
    vis = {i: rel for i, rel in db.session.query(Visit.id, Visit.relation)}

    def acct(rid):
        r = rec.get(rid)
        return f'{r.display_name} ({r.username})' if r else ''

    if kind == 'visits':
        ok = {a.visit_id: a.recipient_id for a in LoginAttempt.query.filter(
            LoginAttempt.success.is_(True), LoginAttempt.visit_id.isnot(None))}
        q = in_range(Visit.query, Visit.created_at).order_by(Visit.created_at.desc()).limit(2000)
        cols = [('created_at', 'Date/time'), ('relation', 'Relationship'),
                ('account', 'Logged in as'), ('status', 'Status'), ('device', 'Device'), ('browser', 'Browser'),
                ('os', 'OS'), ('screen_size', 'Screen'), ('ip_address', 'IP')]
        rows = [{'id': v.id, 'created_at': iso(v.created_at), 'relation': v.relation,
                 'account': acct(ok.get(v.id)), 'status': 'Logged in' if v.id in ok else 'No login',
                 **parse_ua(v.user_agent), 'screen_size': v.screen_size, 'ip_address': v.ip_address} for v in q]
    elif kind == 'logins':
        q = in_range(LoginAttempt.query, LoginAttempt.created_at).order_by(LoginAttempt.created_at.desc()).limit(2000)
        cols = [('created_at', 'Date/time'), ('username', 'Name tried'), ('account', 'Account'),
                ('status', 'Result'), ('relation', 'Relationship'), ('device', 'Device'), ('browser', 'Browser'),
                ('os', 'OS'), ('ip_address', 'IP')]
        rows = [{'id': a.id, 'created_at': iso(a.created_at), 'username': a.username_attempted,
                 'account': acct(a.recipient_id), 'status': 'Success' if a.success else 'Failed',
                 'relation': vis.get(a.visit_id, ''), **parse_ua(a.user_agent), 'ip_address': a.ip_address}
                for a in q]
    elif kind == 'sessions':
        q = in_range(LoginSession.query, LoginSession.started_at).order_by(LoginSession.started_at.desc()).limit(2000)
        cols = [('started_at', 'Started'), ('last_seen_at', 'Last activity'), ('ended_at', 'Ended'),
                ('minutes', 'Minutes'), ('account', 'Account'), ('relation', 'Relationship'), ('status', 'Status')]
        rows = [{'id': s.id, 'started_at': iso(s.started_at), 'last_seen_at': iso(s.last_seen_at),
                 'ended_at': iso(s.ended_at), 'minutes': round(((s.ended_at or s.last_seen_at) - s.started_at)
                                                              .total_seconds() / 60, 1),
                 'account': acct(s.recipient_id), 'relation': vis.get(s.visit_id, ''),
                 'status': 'Active' if s.active else 'Ended'} for s in q]
    elif kind == 'replies':
        sess = {i: v for i, v in db.session.query(LoginSession.id, LoginSession.visit_id)}
        q = in_range(Reply.query, Reply.created_at).order_by(Reply.created_at.desc()).limit(2000)
        cols = [('created_at', 'Date/time'), ('account', 'Account'), ('relation', 'Relationship'),
                ('message', 'Reply')]
        rows = [{'id': r.id, 'created_at': iso(r.created_at), 'account': acct(r.recipient_id),
                 'relation': vis.get(sess.get(r.session_id), ''), 'message': r.message} for r in q]
    elif kind == 'recipients':
        last, n_sess, n_rep = {}, Counter(), Counter()
        for s in LoginSession.query.all():
            n_sess[s.recipient_id] += 1
            if s.started_at and (s.recipient_id not in last or s.started_at > last[s.recipient_id]):
                last[s.recipient_id] = s.started_at
        for r in Reply.query.all():
            n_rep[r.recipient_id] += 1
        cols = [('display_name', 'Name'), ('username', 'Login name'), ('relation_label', 'Relationship'),
                ('status', 'Status'), ('last_login_at', 'Last login'), ('sessions', 'Sessions'),
                ('replies', 'Replies'), ('created_at', 'Created')]
        rows = [{'id': r.id, 'display_name': r.display_name, 'username': r.username,
                 'relation_label': r.relation_label or '', 'status': 'Active' if r.active else 'Disabled',
                 'last_login_at': iso(last.get(r.id)), 'sessions': n_sess[r.id], 'replies': n_rep[r.id],
                 'created_at': iso(r.created_at), 'greeting': r.greeting, 'photo_url': r.photo_url or ''}
                for r in Recipient.query.order_by(Recipient.created_at.desc())]
    else:
        return None, None
    text = request.args.get('q', '').strip().lower()
    status = request.args.get('status', '').strip().lower()
    if text:
        rows = [r for r in rows if any(text in str(v).lower() for v in r.values())]
    if status:
        rows = [r for r in rows if str(r.get('status', '')).lower() == status]
    return cols, rows


@app.get('/api/admin/table/<kind>')
@require_auth('admin')
def admin_table(kind):
    cols, rows = build_rows(kind)
    if rows is None:
        return jsonify(error='Unknown table'), 404
    return jsonify(columns=cols, items=rows)


def csv_safe(v):
    s = '' if v is None else str(v)
    return "'" + s if s[:1] in ('=', '+', '-', '@', '\t', '\r') else s  # block spreadsheet formula injection


@app.get('/api/admin/export/<kind>')
@require_auth('admin')
def admin_export(kind):
    cols, rows = build_rows(kind)
    if rows is None:
        return jsonify(error='Unknown table'), 404
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow([label for _k, label in cols])
    for r in rows:
        w.writerow([csv_safe(r.get(k)) for k, _l in cols])
    return Response('\ufeff' + out.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename=diwali-{kind}.csv'})


@app.get('/api/admin/analytics')
@require_auth('admin')
def admin_analytics():
    visits = Visit.query.all()
    rel = Counter(v.relation.strip().title() for v in visits)
    dev = Counter(parse_ua(v.user_agent)['device'] for v in visits)
    today = now_utc().date()
    days = [(today - timedelta(days=i)).isoformat() for i in range(29, -1, -1)]
    per_day = Counter((v.created_at if v.created_at.tzinfo else v.created_at.replace(tzinfo=timezone.utc))
                      .date().isoformat() for v in visits)
    return jsonify(relationships=rel.most_common(10), devices=dev.most_common(),
                   visits_per_day=[[d, per_day.get(d, 0)] for d in days])


@app.post('/api/admin/recipients')
@require_auth('admin')
def admin_create_recipient():
    data = body_json()
    display_name = str(data.get('display_name', '')).strip()[:80]
    username = str(data.get('username', '')).strip().lower()
    password = str(data.get('password', ''))
    photo = clean_photo(data.get('photo_url'))
    if not display_name or not USERNAME_RE.match(username) or not valid_password(password):
        return jsonify(error='Need a display name, a username (3–40 of a-z 0-9 . _ -) and a password (10–72 chars).'), 400
    if photo is None:
        return jsonify(error='Photo URL must start with https://'), 400
    if Recipient.query.filter_by(username=username).first():
        return jsonify(error='Username already exists.'), 409
    r = Recipient(display_name=display_name, username=username, password_hash=hash_pw(password),
                  relation_label=str(data.get('relation_label', ''))[:50],
                  greeting=str(data.get('greeting') or 'Happy Diwali! 🪔')[:2000], photo_url=photo or None)
    db.session.add(r)
    db.session.flush()
    log_activity('recipient_created', recipient_id=r.id)
    db.session.commit()
    return jsonify(id=r.id, message='Recipient account created.'), 201


@app.patch('/api/admin/recipients/<int:rid>')
@require_auth('admin')
def admin_update_recipient(rid):
    r = db.session.get(Recipient, rid)
    if not r:
        return jsonify(error='Account not found.'), 404
    data = body_json()
    if 'display_name' in data:
        name = str(data['display_name']).strip()[:80]
        if not name:
            return jsonify(error='Display name cannot be empty.'), 400
        r.display_name = name
    if 'relation_label' in data:
        r.relation_label = str(data['relation_label'])[:50]
    if 'greeting' in data:
        r.greeting = str(data['greeting'] or 'Happy Diwali! 🪔')[:2000]
    if 'photo_url' in data:
        photo = clean_photo(data['photo_url'])
        if photo is None:
            return jsonify(error='Photo URL must start with https://'), 400
        r.photo_url = photo or None
    if 'active' in data:
        r.active = bool(data['active'])
        if not r.active:
            end_sessions(r.id)
        log_activity('account_enabled' if r.active else 'account_disabled', recipient_id=r.id)
    db.session.commit()
    return jsonify(message='Account updated.')


@app.post('/api/admin/recipients/<int:rid>/reset-password')
@require_auth('admin')
def admin_reset_password(rid):
    r = db.session.get(Recipient, rid)
    password = str(body_json().get('password', ''))
    if not r:
        return jsonify(error='Account not found.'), 404
    if not valid_password(password):
        return jsonify(error='Use a secret with 10–72 characters.'), 400
    r.password_hash = hash_pw(password)
    end_sessions(r.id)
    log_activity('password_reset_by_admin', recipient_id=r.id)
    db.session.commit()
    return jsonify(message='Password reset. Share the new one privately.')


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '5000')), debug=os.getenv('FLASK_DEBUG') == '1')
