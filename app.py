from flask import Flask, render_template, request, g, redirect, session, url_for, flash, send_file, abort
from datetime import datetime, date, timedelta
import calendar
import pandas as pd
from io import BytesIO
import os
import re
import sqlite3
import random
import string
import hashlib
import binascii
import unicodedata

app_info = {'db_file': os.environ.get('DB_FILE', 'data/database.db')}

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'tajny_klucz')

APP_VERSION = '2.2.0'

# Seed values only - statuses and issue codes live in the database and are managed by admins (Admin > Lists)
DEFAULT_STATUSES = [
    # key, label, color, counts as done
    ('new', 'New', 'amber', 0),
    ('in progress', 'In Progress', 'blue', 0),
    ('on hold', 'On Hold', 'slate', 0),
    ('completed', 'Completed', 'green', 1),
]
STATUS_COLORS = ['amber', 'blue', 'green', 'slate', 'red', 'purple', 'teal', 'orange']

PRIORITIES = [(1, 'Critical'), (2, 'High'), (3, 'Medium'), (4, 'Low'), (5, 'Very low')]
PRIORITY_LABELS = dict(PRIORITIES)

DEFAULT_ISSUE_CODES = ['ServiceNow', 'Tel. Solution', 'SD Tool Review', 'SD Doc.', 'Reporting',
               'KCS', 'IM-PM', 'M&A', 'Resources', 'AI', 'Automation']

FIELD_LABELS = {
    'project_name': 'Project name', 'start_date': 'Start date', 'description': 'Description',
    'eta_date': 'ETA', 'responsible': 'Responsible', 'status': 'Status',
    'issue_code': 'Issue code', 'priority': 'Priority', 'status_comment': 'Status / comments',
}
# Fields changed through the edit form (status_comment is now fed by updates/comments)
EDITABLE_FIELDS = ['project_name', 'description', 'issue_code', 'priority', 'responsible',
                   'start_date', 'eta_date', 'status']

METRIC_KINDS = [('single', 'Single value'), ('before_after', 'Before / after')]

DEFAULT_METRICS = [
    # name, unit, kind, show total on dashboard, help text
    ('Hours saved / month', 'h', 'single', 1, 'Estimated working hours saved per month thanks to the initiative.'),
    ('Tickets reduced / month', 'tickets', 'single', 1, 'How many tickets per month are avoided or deflected.'),
    ('CSAT', '%', 'before_after', 0, 'Customer satisfaction before and after the change.'),
]


# ---------------------------------------------------------------- database

def get_db():
    if not hasattr(g, 'sqlite_db'):
        conn = sqlite3.connect(app_info['db_file'])
        conn.row_factory = sqlite3.Row
        g.sqlite_db = conn
    return g.sqlite_db


@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


def _columns(conn, table):
    return {r[1] for r in conn.execute('PRAGMA table_info({})'.format(table))}


def guess_full_name(login_name):
    """'MichalGrysinski' -> 'Michal Grysinski', 'Angelika.Wasilewska' -> 'Angelika Wasilewska'."""
    n = login_name.replace('.', ' ').replace('_', ' ')
    n = re.sub(r'(?<=[a-z])(?=[A-Z])', ' ', n)
    return ' '.join(w[:1].upper() + w[1:] for w in n.split())


def ensure_schema():
    """Non-destructive migrations: only adds tables / columns that are missing."""
    conn = sqlite3.connect(app_info['db_file'])
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS app_meta (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS initiative_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, initiative_id INTEGER NOT NULL,
            changed_by TEXT, changed_at TEXT, action TEXT, field TEXT, old_value TEXT, new_value TEXT);
        CREATE TABLE IF NOT EXISTS initiative_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT, initiative_id INTEGER NOT NULL,
            author TEXT, created_at TEXT, body TEXT, status_change TEXT, imported INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS metric_definitions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, unit TEXT,
            kind TEXT NOT NULL DEFAULT 'single', show_total INTEGER DEFAULT 0,
            help_text TEXT, is_active INTEGER DEFAULT 1, sort_order INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS statuses (
            id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL UNIQUE, label TEXT NOT NULL,
            color TEXT DEFAULT 'slate', is_done INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1, sort_order INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS issue_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            is_active INTEGER DEFAULT 1, sort_order INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS initiative_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT, initiative_id INTEGER NOT NULL, metric_id INTEGER NOT NULL,
            value_before REAL, value_after REAL, UNIQUE(initiative_id, metric_id));
    ''')

    if 'priority' not in _columns(conn, 'initiatives'):
        conn.execute('ALTER TABLE initiatives ADD COLUMN priority INTEGER DEFAULT 3')
    if 'full_name' not in _columns(conn, 'users'):
        conn.execute('ALTER TABLE users ADD COLUMN full_name TEXT')
    missing = conn.execute("SELECT id, name FROM users WHERE full_name IS NULL OR full_name = ''").fetchall()
    if missing:
        # Prefer the spelling people already used in the Responsible field (keeps Polish letters)
        spellings = {}
        for (resp,) in conn.execute('SELECT responsible FROM initiatives').fetchall():
            for part in split_people(resp):
                counts = spellings.setdefault(norm_name(part), {})
                counts[part] = counts.get(part, 0) + 1
        for uid, name in missing:
            found = spellings.get(norm_name(name))
            best = max(found, key=lambda s: (found[s], sum(not c.isascii() for c in s))) if found else guess_full_name(name)
            conn.execute('UPDATE users SET full_name = ? WHERE id = ?', [best, uid])

    if conn.execute('SELECT COUNT(*) FROM statuses').fetchone()[0] == 0:
        for n, (key, label, color, done) in enumerate(DEFAULT_STATUSES):
            conn.execute('INSERT INTO statuses(key, label, color, is_done, sort_order) VALUES (?,?,?,?,?)',
                         [key, label, color, done, n])
    if conn.execute('SELECT COUNT(*) FROM issue_codes').fetchone()[0] == 0:
        codes = list(DEFAULT_ISSUE_CODES)
        for (c,) in conn.execute("SELECT DISTINCT TRIM(issue_code) FROM initiatives WHERE TRIM(COALESCE(issue_code, '')) <> ''"):
            if c.lower() not in [x.lower() for x in codes]:
                codes.append(c)
        for n, c in enumerate(codes):
            conn.execute('INSERT INTO issue_codes(name, sort_order) VALUES (?,?)', [c, n])
    # Statuses used in data but unknown to the list (e.g. typed on the old server) stay visible
    for (k,) in conn.execute("SELECT DISTINCT status FROM initiatives WHERE status IS NOT NULL AND status <> '' "
                             "AND status NOT IN (SELECT key FROM statuses)").fetchall():
        conn.execute("INSERT INTO statuses(key, label, sort_order) VALUES (?, ?, 99)", [k, k.title()])

    if conn.execute('SELECT COUNT(*) FROM metric_definitions').fetchone()[0] == 0:
        for n, (name, unit, kind, total, help_text) in enumerate(DEFAULT_METRICS):
            conn.execute('''INSERT INTO metric_definitions(name, unit, kind, show_total, help_text, sort_order)
                            VALUES (?,?,?,?,?,?)''', [name, unit, kind, total, help_text, n])

    # One-time: turn the old single "status comment" into the first entry of the updates timeline
    if not conn.execute("SELECT 1 FROM app_meta WHERE key = 'status_comments_migrated'").fetchone():
        for row in conn.execute("SELECT id, status_comment, last_edited_by, last_edited_at FROM initiatives "
                                "WHERE TRIM(COALESCE(status_comment, '')) <> ''").fetchall():
            conn.execute('''INSERT INTO initiative_updates(initiative_id, author, created_at, body, imported)
                            VALUES (?,?,?,?,1)''', [row[0], row[2], row[3] or '', row[1].strip()])
        conn.execute("INSERT INTO app_meta(key, value) VALUES ('status_comments_migrated', ?)",
                     [datetime.now().isoformat(timespec='seconds')])
    conn.commit()
    conn.close()


# ---------------------------------------------------------------- lists (statuses, issue codes)

def get_statuses(active_only=True):
    if not hasattr(g, 'statuses_all'):
        g.statuses_all = [dict(r) for r in get_db().execute('SELECT * FROM statuses ORDER BY sort_order, id').fetchall()]
    return [st for st in g.statuses_all if st['is_active'] or not active_only]


def status_labels():
    return {st['key']: st['label'] for st in get_statuses(False)}


def status_colors():
    return {st['key']: st['color'] for st in get_statuses(False)}


def done_keys():
    return {st['key'] for st in get_statuses(False) if st['is_done']}


def get_issue_codes(active_only=True):
    sql = 'SELECT name FROM issue_codes {} ORDER BY sort_order, id'.format('WHERE is_active' if active_only else '')
    return [r['name'] for r in get_db().execute(sql).fetchall()]


# ---------------------------------------------------------------- dates

MONTHS = {m.lower(): i for i, m in enumerate(calendar.month_name) if m}
MONTHS.update({m.lower(): i for i, m in enumerate(calendar.month_abbr) if m})
MONTHS['sept'] = 9


def parse_date_ex(value, end_of_period=False):
    """Parse the many date styles found in the data.

    Returns (date, precision) with precision 'day' or 'month', or (None, None).
    Ambiguous numeric dates like 04/05/2025 (could be April 5 or May 4) are not guessed.
    Month-only values ('June 2025', '05-2025') resolve to the first day, or the last day
    when end_of_period is True (used for ETA).
    """
    if not value:
        return None, None
    v = re.sub(r'[\u200b\u200c\u200d\ufeff]', '', str(value)).strip().rstrip('.')
    if not v:
        return None, None

    def month_result(y, m):
        if not (1 <= m <= 12 and 1900 < y < 2200):
            return None, None
        d = calendar.monthrange(y, m)[1] if end_of_period else 1
        return date(y, m, d), 'month'

    # ISO 2025-04-10
    m = re.fullmatch(r'(\d{4})-(\d{1,2})-(\d{1,2})', v)
    if m:
        try:
            return date(int(m[1]), int(m[2]), int(m[3])), 'day'
        except ValueError:
            return None, None

    # dotted = European d.m.yyyy
    m = re.fullmatch(r'(\d{1,2})\.(\d{1,2})\.(\d{4})', v)
    if m:
        try:
            return date(int(m[3]), int(m[2]), int(m[1])), 'day'
        except ValueError:
            return None, None

    # a/b/yyyy or a-b-yyyy: decide day/month order only when unambiguous
    m = re.fullmatch(r'(\d{1,2})[/-](\d{1,2})[/-](\d{4})', v)
    if m:
        a, b, y = int(m[1]), int(m[2]), int(m[3])
        if a > 12 and b <= 12:
            d_, mo = a, b
        elif b > 12 and a <= 12:
            d_, mo = b, a
        elif a == b:
            d_, mo = a, b
        else:
            return None, None
        try:
            return date(y, mo, d_), 'day'
        except ValueError:
            return None, None

    # mm-yyyy / mm/yyyy
    m = re.fullmatch(r'(\d{1,2})[/-](\d{4})', v)
    if m:
        return month_result(int(m[2]), int(m[1]))

    # 'June 10, 2025' / 'Jun 10 2025'
    m = re.fullmatch(r'([A-Za-z]+)\.?\s+(\d{1,2}),?\s+(\d{4})', v)
    if m and m[1].lower() in MONTHS:
        try:
            return date(int(m[3]), MONTHS[m[1].lower()], int(m[2])), 'day'
        except ValueError:
            return None, None

    # 'June 2025' / 'Sept 2025'
    m = re.fullmatch(r'([A-Za-z]+)\.?,?\s+(\d{4})', v)
    if m and m[1].lower() in MONTHS:
        return month_result(int(m[2]), MONTHS[m[1].lower()])

    return None, None


def parse_date(value, end_of_period=False):
    return parse_date_ex(value, end_of_period)[0]


# ---------------------------------------------------------------- people

def norm_name(s):
    """Lower-case, accent-free, no spaces: 'Michał Grysiński' -> 'michalgrysinski'."""
    s = (s or '').replace('ł', 'l').replace('Ł', 'L')
    s = unicodedata.normalize('NFKD', s)
    s = ''.join(c for c in s if not unicodedata.combining(c))
    return re.sub(r'[^a-z0-9]', '', s.lower())


def split_people(text):
    parts = re.split(r'\s*(?:,|/|\||;|&|\band\b|\s-\s)\s*', text or '')
    return [p.strip() for p in parts if p and p.strip()]


def get_people():
    """Active users that can be picked as responsible."""
    rows = get_db().execute('''SELECT name, COALESCE(NULLIF(full_name, ''), name) AS full_name
                               FROM users WHERE is_active ORDER BY full_name COLLATE NOCASE''').fetchall()
    return [dict(r) for r in rows]


def match_people(responsible, people):
    """Split the free-text responsible field into (matched user logins, unmatched names)."""
    index = {}
    for p in people:
        index[norm_name(p['full_name'])] = p['name']
        index[norm_name(p['name'])] = p['name']
    matched, other = [], []
    for part in split_people(responsible):
        login = index.get(norm_name(part))
        if login and login not in matched:
            matched.append(login)
        elif not login:
            other.append(part)
    return matched, other


def is_responsible(login_name, responsible):
    if not login_name:
        return False
    row = get_db().execute('SELECT full_name FROM users WHERE name = ?', [login_name]).fetchone()
    keys = {norm_name(login_name), norm_name(row['full_name'] if row else '')} - {''}
    return any(norm_name(p) in keys for p in split_people(responsible))


def can_manage(login, initiative):
    """Admins, the last editor (original rule) and people listed as responsible may edit and comment."""
    if not login.is_valid:
        return False
    return bool(login.is_admin or initiative['last_edited_by'] == login.user
                or is_responsible(login.user, initiative['responsible']))


# ---------------------------------------------------------------- metrics

def get_metric_definitions(active_only=True):
    sql = 'SELECT * FROM metric_definitions {} ORDER BY sort_order, id'.format('WHERE is_active' if active_only else '')
    return [dict(r) for r in get_db().execute(sql).fetchall()]


def get_initiative_metrics(initiative_id):
    rows = get_db().execute('''SELECT m.*, d.name, d.unit, d.kind, d.help_text, d.is_active
                               FROM initiative_metrics m JOIN metric_definitions d ON d.id = m.metric_id
                               WHERE m.initiative_id = ? ORDER BY d.sort_order, d.id''', [initiative_id]).fetchall()
    return [dict(r) for r in rows]


def fmt_num(v):
    if v is None:
        return ''
    return ('{:,.0f}' if float(v).is_integer() else '{:,.1f}').format(v).replace(',', ' ')


def to_float(s):
    s = (s or '').strip().replace(',', '.').replace(' ', '')
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def save_metrics(db, initiative_id, user, log=True):
    existing = {m['metric_id']: m for m in get_initiative_metrics(initiative_id)}
    changes = 0
    for d in get_metric_definitions():
        before = to_float(request.form.get('metric_{}_before'.format(d['id'])))
        after = to_float(request.form.get('metric_{}_after'.format(d['id'])))
        if d['kind'] == 'single':
            before = None
        old = existing.get(d['id'])
        old_pair = (old['value_before'], old['value_after']) if old else (None, None)
        if old_pair == (before, after):
            continue
        if before is None and after is None:
            db.execute('DELETE FROM initiative_metrics WHERE initiative_id = ? AND metric_id = ?', [initiative_id, d['id']])
        else:
            db.execute('''INSERT INTO initiative_metrics(initiative_id, metric_id, value_before, value_after)
                          VALUES (?,?,?,?) ON CONFLICT(initiative_id, metric_id)
                          DO UPDATE SET value_before = excluded.value_before, value_after = excluded.value_after''',
                       [initiative_id, d['id'], before, after])
        if log:
            def show(pair):
                b, a = pair
                if b is None and a is None:
                    return ''
                return '{} → {}'.format(fmt_num(b), fmt_num(a)) if d['kind'] == 'before_after' else fmt_num(a)
            log_history(db, initiative_id, user, 'updated', 'metric:' + d['name'], show(old_pair), show((before, after)))
        changes += 1
    return changes


# ---------------------------------------------------------------- initiatives helpers

def normalize_issue_code(code):
    for c in get_issue_codes(False):
        if code and c.lower() == code.lower():
            return c
    return code


def display_date(d, precision, raw):
    if not d:
        return raw.strip() if raw and raw.strip() else '—'
    return d.strftime('%b %Y') if precision == 'month' else d.strftime('%d %b %Y')


def enrich(row):
    """Turns a DB row into a dict with computed fields used by the UI."""
    d = dict(row)
    d['issue_code'] = normalize_issue_code(d.get('issue_code'))
    d['status_label'] = status_labels().get(d.get('status'), d.get('status') or '—')
    d['status_color'] = status_colors().get(d.get('status'), 'slate')
    d['priority'] = d.get('priority') or 3
    d['priority_label'] = PRIORITY_LABELS.get(d['priority'], str(d['priority']))
    start, start_prec = parse_date_ex(d.get('start_date'))
    eta, eta_prec = parse_date_ex(d.get('eta_date'), end_of_period=True)
    done = d.get('status') in done_keys()
    d['is_done'] = done
    today = date.today()
    d['start_precision'], d['eta_precision'] = start_prec, eta_prec
    d['start_iso'] = start.isoformat() if start else ''
    d['eta_iso'] = eta.isoformat() if eta else ''
    d['start_display'] = display_date(start, start_prec, d.get('start_date'))
    d['eta_display'] = display_date(eta, eta_prec, d.get('eta_date'))
    d['days_left'] = (eta - today).days if eta else None
    d['is_overdue'] = bool(eta and eta < today and not done)
    d['due_soon'] = bool(eta and 0 <= (eta - today).days <= 14 and not done)
    if done:
        d['time_progress'] = 100
    elif start and eta and eta > start:
        d['time_progress'] = max(0, min(100, round((today - start).days / (eta - start).days * 100)))
    else:
        d['time_progress'] = None
    return d


def form_text(name):
    return (request.form.get(name) or '').strip()


def form_date(name):
    """Exact dates are stored as dd.mm.yyyy (like existing data); anything else is kept as typed."""
    v = form_text(name)
    d, precision = parse_date_ex(v)
    return d.strftime('%d.%m.%Y') if d and precision == 'day' else v


def form_responsible(people):
    by_login = {p['name']: p['full_name'] for p in people}
    names = [by_login[l] for l in request.form.getlist('responsible_user') if l in by_login]
    if request.form.get('responsible_other_on'):
        names += [n for n in split_people(form_text('responsible_other')) if n not in names]
    return ', '.join(names)


def form_values(people):
    try:
        priority = int(request.form.get('priority') or 3)
    except ValueError:
        priority = 3
    return {
        'project_name': form_text('project_name'),
        'description': form_text('description'),
        'issue_code': normalize_issue_code(form_text('issue_code')),
        'priority': priority if priority in PRIORITY_LABELS else 3,
        'responsible': form_responsible(people),
        'start_date': form_date('start_date'),
        'eta_date': form_date('eta_date'),
        'status': form_text('status') if form_text('status') in status_labels() else get_statuses()[0]['key'],
    }


def log_history(db, initiative_id, user, action, field=None, old=None, new=None):
    db.execute('''INSERT INTO initiative_history(initiative_id, changed_by, changed_at, action, field, old_value, new_value)
                  VALUES (?,?,?,?,?,?,?)''',
               [initiative_id, user, now_str(), action, field,
                None if old is None else str(old), None if new is None else str(new)])


def now_str():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def field_label(field):
    if field and field.startswith('metric:'):
        return field[7:]
    return FIELD_LABELS.get(field, field)


app.add_template_filter(split_people, 'people')


@app.context_processor
def inject_globals():
    try:
        lists = dict(STATUSES=[(st['key'], st['label']) for st in get_statuses()], STATUS_LABELS=status_labels(),
                     STATUS_COLORS=status_colors(), ISSUE_CODES=get_issue_codes())
    except sqlite3.Error:
        lists = dict(STATUSES=[], STATUS_LABELS={}, STATUS_COLORS={}, ISSUE_CODES=[])
    return dict(**lists, APP_VERSION=APP_VERSION, PRIORITIES=PRIORITIES, COLOR_NAMES=STATUS_COLORS,
                FIELD_LABELS=FIELD_LABELS, PRIORITY_LABELS=PRIORITY_LABELS,
                METRIC_KINDS=METRIC_KINDS, field_label=field_label, fmt_num=fmt_num)


# ---------------------------------------------------------------- auth

class UserPass:

    def __init__(self, user='', password=''):
        self.user = user
        self.password = password
        self.email = ''
        self.is_valid = False
        self.is_admin = False

    def hash_password(self):
        """Hash a password for storing."""
        # the value generated using os.urandom(60)
        os_urandom_static = b"ID_\x12p:\x8d\xe7&\xcb\xf0=H1\xc1\x16\xac\xe5BX\xd7\xd6j\xe3i\x11\xbe\xaa\x05\xccc\xc2\xe8K\xcf\xf1\xac\x9bFy(\xfbn.`\xe9\xcd\xdd'\xdf`~vm\xae\xf2\x93WD\x04"
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha512', self.password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')

    def verify_password(self, stored_password, provided_password):
        """Verify a stored password against one provided by user"""
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'),
                                      salt.encode('ascii'), 100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password

    def get_random_user_pasword(self):
        self.user = ''.join(random.choice(string.ascii_lowercase) for i in range(3))
        self.password = ''.join(random.choice(string.ascii_letters) for i in range(3))

    def login_user(self):
        db = get_db()
        user_record = db.execute('select id, name, email, password, is_active, is_admin from users where name=?',
                                 [self.user]).fetchone()
        if user_record is not None and user_record['is_active'] and \
                self.verify_password(user_record['password'], self.password):
            return user_record
        self.user = None
        self.password = None
        return None

    def get_user_info(self):
        db_user = get_db().execute('select name, email, is_active, is_admin from users where name=?',
                                   [self.user]).fetchone()
        if db_user is None:
            self.is_valid = False
            self.is_admin = False
            self.email = ''
        elif db_user['is_active'] != 1:
            self.is_valid = False
            self.is_admin = False
            self.email = db_user['email']
        else:
            self.is_valid = True
            self.is_admin = db_user['is_admin']
            self.email = db_user['email']


def current_login():
    login = UserPass(session.get('user'))
    login.get_user_info()
    return login


def require_admin():
    login = current_login()
    if not login.is_valid or not login.is_admin:
        return login, redirect(url_for('login'))
    return login, None


# ---------------------------------------------------------------- setup

@app.route('/init_app')
def init_app():
    db = get_db()
    active_admins = db.execute('select count(*) as cnt from users where is_active and is_admin;').fetchone()
    if active_admins is not None and active_admins['cnt'] > 0:
        print('Application is already set-up. Nothing to do..')
        return redirect(url_for('initiatives'))

    user_pass = UserPass()
    user_pass.get_random_user_pasword()
    db.execute('''insert into users(name, email, password, is_active, is_admin, full_name)
                  values(?,?,?,True, True, ?);''',
               [user_pass.user, 'noone@nowhere.no', user_pass.hash_password(), user_pass.user])
    db.commit()
    print('User {} with password {} has been created'.format(user_pass.user, user_pass.password))
    return redirect(url_for('initiatives'))


# ---------------------------------------------------------------- initiatives

@app.route('/')
@app.route('/initiatives')
def initiatives():
    login = current_login()
    db = get_db()
    rows = db.execute('SELECT * FROM initiatives ORDER BY id DESC').fetchall()
    items = [enrich(r) for r in rows]

    counts = dict(db.execute('SELECT initiative_id, COUNT(*) FROM initiative_updates GROUP BY initiative_id').fetchall())
    for i in items:
        i['updates_count'] = counts.get(i['id'], 0)

    by_status = [dict(st, count=sum(1 for i in items if i['status'] == st['key'])) for st in get_statuses(False)]
    stats = {
        'total': len(items),
        'overdue': sum(1 for i in items if i['is_overdue']),
        # inactive statuses only appear while still used
        'by_status': [st for st in by_status if st['is_active'] or st['count']],
    }
    impact = db.execute('''SELECT d.name, d.unit, SUM(m.value_after) AS total, COUNT(m.id) AS n
                           FROM metric_definitions d LEFT JOIN initiative_metrics m ON m.metric_id = d.id
                           WHERE d.is_active AND d.show_total AND d.kind = 'single'
                           GROUP BY d.id ORDER BY d.sort_order, d.id''').fetchall()

    people = set()
    for i in items:
        people.update(split_people(i['responsible']))
    responsibles = sorted(people, key=lambda s: norm_name(s))
    codes_in_use = sorted({i['issue_code'] for i in items if i['issue_code']}, key=str.lower)

    return render_template('initiatives.html', title="Initiatives", login=login, initiatives=items,
                           stats=stats, impact=impact, responsibles=responsibles, codes_in_use=codes_in_use)


@app.route('/initiative/<int:initiative_id>')
def initiative_detail(initiative_id):
    login = current_login()
    db = get_db()
    row = db.execute('SELECT * FROM initiatives WHERE id = ?', [initiative_id]).fetchone()
    if row is None:
        abort(404)
    history = db.execute('''SELECT * FROM initiative_history WHERE initiative_id = ?
                            ORDER BY changed_at DESC, id DESC''', [initiative_id]).fetchall()
    updates = db.execute('''SELECT u.*, COALESCE(NULLIF(us.full_name, ''), u.author) AS author_name
                            FROM initiative_updates u LEFT JOIN users us ON us.name = u.author
                            WHERE u.initiative_id = ? ORDER BY u.created_at DESC, u.id DESC''',
                         [initiative_id]).fetchall()
    return render_template('initiative_detail.html', title=row['project_name'], login=login,
                           i=enrich(row), history=history, updates=updates,
                           metrics=get_initiative_metrics(initiative_id), can_manage=can_manage(login, row))


@app.route('/initiative/<int:initiative_id>/update', methods=['POST'])
def add_update(initiative_id):
    login = current_login()
    db = get_db()
    row = db.execute('SELECT * FROM initiatives WHERE id = ?', [initiative_id]).fetchone()
    if row is None:
        abort(404)
    if not can_manage(login, row):
        flash('Only the responsible people and admins can post updates.', 'error')
        return redirect(url_for('initiative_detail', initiative_id=initiative_id))

    body = form_text('body')
    new_status = form_text('status')
    status_change = None
    if new_status in status_labels() and new_status != row['status']:
        status_change = '{}|{}'.format(row['status'] or '', new_status)
    if not body and not status_change:
        flash('Write an update or pick a new status.', 'error')
        return redirect(url_for('initiative_detail', initiative_id=initiative_id))

    ts = now_str()
    db.execute('''INSERT INTO initiative_updates(initiative_id, author, created_at, body, status_change)
                  VALUES (?,?,?,?,?)''', [initiative_id, login.user, ts, body, status_change])
    db.execute('''UPDATE initiatives SET status = ?, status_comment = CASE WHEN ? <> '' THEN ? ELSE status_comment END,
                  last_edited_by = ?, last_edited_at = ? WHERE id = ?''',
               [new_status if status_change else row['status'], body, body, login.user, ts, initiative_id])
    if status_change:
        log_history(db, initiative_id, login.user, 'updated', 'status', row['status'], new_status)
    db.commit()
    flash('Update posted.', 'success')
    return redirect(url_for('initiative_detail', initiative_id=initiative_id) + '#updates')


@app.route('/update/<int:update_id>/delete', methods=['POST'])
def delete_update(update_id):
    login = current_login()
    db = get_db()
    upd = db.execute('SELECT * FROM initiative_updates WHERE id = ?', [update_id]).fetchone()
    if upd is None:
        abort(404)
    if not (login.is_valid and (login.is_admin or upd['author'] == login.user)):
        flash('You can only delete your own updates.', 'error')
    else:
        db.execute('DELETE FROM initiative_updates WHERE id = ?', [update_id])
        latest = db.execute('''SELECT body FROM initiative_updates WHERE initiative_id = ? AND TRIM(COALESCE(body, '')) <> ''
                               ORDER BY created_at DESC, id DESC LIMIT 1''', [upd['initiative_id']]).fetchone()
        db.execute('UPDATE initiatives SET status_comment = ? WHERE id = ?',
                   [latest['body'] if latest else '', upd['initiative_id']])
        db.commit()
        flash('Update deleted.', 'success')
    return redirect(url_for('initiative_detail', initiative_id=upd['initiative_id']) + '#updates')


def render_form(login, title, i, people):
    matched, other = match_people(i['responsible'] if i else '', people)
    if not i and not matched and not other:
        matched = [login.user] if any(p['name'] == login.user for p in people) else []
    values = {}
    if i:
        for m in get_initiative_metrics(i['id']):
            values[m['metric_id']] = m
    return render_template('initiative_form.html', title=title, login=login, i=i, people=people,
                           selected_people=matched, other_people=', '.join(other),
                           metric_defs=get_metric_definitions(), metric_values=values)


@app.route('/new_initiative', methods=['GET', 'POST'])
def new_initiative():
    login = current_login()
    if not login.is_valid:
        return redirect(url_for('login'))
    people = get_people()

    if request.method == 'POST':
        db = get_db()
        v = form_values(people)
        ts = now_str()
        first_update = form_text('first_update')
        cur = db.execute('''
            INSERT INTO initiatives (project_name, start_date, description, eta_date, responsible,
                                     status_comment, status, last_edited_by, last_edited_at, issue_code, priority)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            [v['project_name'], v['start_date'], v['description'], v['eta_date'], v['responsible'],
             first_update, v['status'], login.user, ts, v['issue_code'], v['priority']])
        new_id = cur.lastrowid
        log_history(db, new_id, login.user, 'created')
        if first_update:
            db.execute('''INSERT INTO initiative_updates(initiative_id, author, created_at, body)
                          VALUES (?,?,?,?)''', [new_id, login.user, ts, first_update])
        save_metrics(db, new_id, login.user, log=False)
        db.commit()
        flash('Initiative "{}" created.'.format(v['project_name']), 'success')
        return redirect(url_for('initiative_detail', initiative_id=new_id))

    return render_form(login, 'New initiative', None, people)


@app.route('/edit_initiative/<int:initiative_id>', methods=['GET', 'POST'])
def edit_initiative(initiative_id):
    login = current_login()
    if not login.is_valid:
        return redirect(url_for('login'))

    db = get_db()
    initiative = db.execute('SELECT * FROM initiatives WHERE id = ?', [initiative_id]).fetchone()
    if initiative is None:
        abort(404)
    if not can_manage(login, initiative):
        flash("You don't have permission to edit this initiative.", 'error')
        return redirect(url_for('initiative_detail', initiative_id=initiative_id))
    people = get_people()

    if request.method == 'POST':
        new_values = form_values(people)
        old_values = {f: (initiative[f] if initiative[f] is not None else '') for f in EDITABLE_FIELDS}
        old_values['issue_code'] = normalize_issue_code(old_values['issue_code'])
        old_values['priority'] = initiative['priority'] or 3
        # Unchanged people in a different order/spelling are not a change
        if norm_name(''.join(sorted(split_people(old_values['responsible'])))) == \
                norm_name(''.join(sorted(split_people(new_values['responsible'])))):
            new_values['responsible'] = old_values['responsible']
        changes = [(f, old_values[f], new_values[f]) for f in EDITABLE_FIELDS
                   if str(old_values[f]) != str(new_values[f])]

        if changes:
            db.execute('''
                UPDATE initiatives SET project_name=?, start_date=?, description=?, eta_date=?, responsible=?,
                       status=?, last_edited_by=?, last_edited_at=?, issue_code=?, priority=?
                WHERE id=?''',
                [new_values['project_name'], new_values['start_date'], new_values['description'],
                 new_values['eta_date'], new_values['responsible'], new_values['status'], login.user, now_str(),
                 new_values['issue_code'], new_values['priority'], initiative_id])
            for field, old, new in changes:
                if field == 'priority':
                    old, new = PRIORITY_LABELS.get(old, old), PRIORITY_LABELS.get(new, new)
                log_history(db, initiative_id, login.user, 'updated', field, old, new)
        metric_changes = save_metrics(db, initiative_id, login.user)
        db.commit()

        total = len(changes) + metric_changes
        flash('Saved {} change(s).'.format(total) if total else 'No changes to save.', 'success' if total else 'info')
        return redirect(url_for('initiative_detail', initiative_id=initiative_id))

    return render_form(login, 'Edit initiative', enrich(initiative), people)


@app.route('/delete_initiative/<int:initiative_id>', methods=['POST'])
def delete_initiative(initiative_id):
    login = current_login()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    db = get_db()
    for table in ('initiative_history', 'initiative_updates', 'initiative_metrics'):
        db.execute('DELETE FROM {} WHERE initiative_id = ?'.format(table), [initiative_id])
    db.execute('DELETE FROM initiatives WHERE id = ?', [initiative_id])
    db.commit()
    flash('Initiative deleted.', 'success')
    return redirect(url_for('initiatives'))


@app.route('/export_initiatives')
def export_initiatives():
    login = current_login()
    if not login.is_valid:
        return redirect(url_for('login'))

    db = get_db()
    items = [enrich(r) for r in db.execute('SELECT * FROM initiatives ORDER BY id DESC').fetchall()]
    defs = get_metric_definitions(active_only=False)
    values = {}
    for r in db.execute('SELECT * FROM initiative_metrics').fetchall():
        values[(r['initiative_id'], r['metric_id'])] = r

    records = []
    for i in items:
        rec = {
            'ID': i['id'], 'Project': i['project_name'], 'Status': i['status_label'], 'Priority': i['priority_label'],
            'Issue code': i['issue_code'], 'Responsible': i['responsible'],
            'Start date': i['start_date'], 'ETA': i['eta_date'], 'Overdue': 'Yes' if i['is_overdue'] else '',
            'Description': i['description'], 'Latest update': i['status_comment'],
            'Last edited by': i['last_edited_by'], 'Last edited at': i['last_edited_at'],
        }
        for d in defs:
            m = values.get((i['id'], d['id']))
            label = '{} [{}]'.format(d['name'], d['unit']) if d['unit'] else d['name']
            if d['kind'] == 'before_after':
                rec[label + ' before'] = m['value_before'] if m else None
                rec[label + ' after'] = m['value_after'] if m else None
            else:
                rec[label] = m['value_after'] if m else None
        records.append(rec)
    df = pd.DataFrame(records)

    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Initiatives')
        ws = writer.sheets['Initiatives']
        ws.autofilter(0, 0, max(len(df), 1), max(len(df.columns) - 1, 0))
        ws.freeze_panes(1, 0)
        widths = [6, 30, 13, 10, 15, 25, 12, 12, 9, 50, 50, 16, 19]
        for col in range(len(df.columns)):
            ws.set_column(col, col, widths[col] if col < len(widths) else 16)

        upd = pd.read_sql_query('''SELECT u.initiative_id AS "Initiative ID", i.project_name AS "Project",
                                          u.created_at AS "Date", u.author AS "Author", u.body AS "Update"
                                   FROM initiative_updates u JOIN initiatives i ON i.id = u.initiative_id
                                   ORDER BY u.initiative_id DESC, u.created_at DESC''', db)
        upd.to_excel(writer, index=False, sheet_name='Updates')
        ws2 = writer.sheets['Updates']
        ws2.freeze_panes(1, 0)
        for col, w in enumerate([12, 30, 19, 18, 80]):
            ws2.set_column(col, col, w)
    output.seek(0)

    filename = 'initiatives_{}.xlsx'.format(datetime.now().strftime('%Y%m%d_%H%M%S'))
    return send_file(output, as_attachment=True, download_name=filename,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


# ---------------------------------------------------------------- impact metrics (admin)

@app.route('/metrics', methods=['GET', 'POST'])
def metrics():
    login, denied = require_admin()
    if denied:
        return denied
    db = get_db()

    if request.method == 'POST':
        metric_id = request.form.get('id')
        name = form_text('name')
        kind = form_text('kind') if form_text('kind') in dict(METRIC_KINDS) else 'single'
        fields = [name, form_text('unit'), kind, 1 if request.form.get('show_total') and kind == 'single' else 0,
                  form_text('help_text')]
        if not name:
            flash('Metric name cannot be empty.', 'error')
            return redirect(url_for('metrics'))
        try:
            if metric_id:
                db.execute('UPDATE metric_definitions SET name=?, unit=?, kind=?, show_total=?, help_text=? WHERE id=?',
                           fields + [metric_id])
                flash('Metric "{}" saved.'.format(name), 'success')
            else:
                order = db.execute('SELECT COALESCE(MAX(sort_order), 0) + 1 FROM metric_definitions').fetchone()[0]
                db.execute('''INSERT INTO metric_definitions(name, unit, kind, show_total, help_text, sort_order)
                              VALUES (?,?,?,?,?,?)''', fields + [order])
                flash('Metric "{}" added.'.format(name), 'success')
            db.commit()
        except sqlite3.IntegrityError:
            flash('A metric named "{}" already exists.'.format(name), 'error')
        return redirect(url_for('metrics'))

    defs = db.execute('''SELECT d.*, COUNT(m.id) AS used FROM metric_definitions d
                         LEFT JOIN initiative_metrics m ON m.metric_id = d.id
                         GROUP BY d.id ORDER BY d.sort_order, d.id''').fetchall()
    return render_template('metrics.html', title='Impact metrics', login=login, defs=defs)


@app.route('/metrics/<int:metric_id>/<action>', methods=['POST'])
def metric_action(metric_id, action):
    login, denied = require_admin()
    if denied:
        return denied
    db = get_db()
    d = db.execute('SELECT * FROM metric_definitions WHERE id = ?', [metric_id]).fetchone()
    if d is None:
        abort(404)
    if action == 'toggle':
        db.execute('UPDATE metric_definitions SET is_active = 1 - COALESCE(is_active, 1) WHERE id = ?', [metric_id])
    elif action in ('up', 'down'):
        defs = [r['id'] for r in db.execute('SELECT id FROM metric_definitions ORDER BY sort_order, id')]
        idx = defs.index(metric_id)
        swap = idx - 1 if action == 'up' else idx + 1
        if 0 <= swap < len(defs):
            defs[idx], defs[swap] = defs[swap], defs[idx]
            for n, mid in enumerate(defs):
                db.execute('UPDATE metric_definitions SET sort_order = ? WHERE id = ?', [n, mid])
    elif action == 'delete':
        used = db.execute('SELECT COUNT(*) FROM initiative_metrics WHERE metric_id = ?', [metric_id]).fetchone()[0]
        if used:
            flash('Metric is used by {} initiative(s) – deactivate it instead.'.format(used), 'error')
            return redirect(url_for('metrics'))
        db.execute('DELETE FROM metric_definitions WHERE id = ?', [metric_id])
        flash('Metric deleted.', 'success')
    db.commit()
    return redirect(url_for('metrics'))


# ---------------------------------------------------------------- lists admin (statuses & issue codes)

def _reorder(db, table, item_id, direction):
    ids = [r[0] for r in db.execute('SELECT id FROM {} ORDER BY sort_order, id'.format(table))]
    if item_id not in ids:
        return
    idx = ids.index(item_id)
    swap = idx - 1 if direction == 'up' else idx + 1
    if 0 <= swap < len(ids):
        ids[idx], ids[swap] = ids[swap], ids[idx]
    for n, i in enumerate(ids):
        db.execute('UPDATE {} SET sort_order = ? WHERE id = ?'.format(table), [n, i])


@app.route('/lists')
def lists():
    login, denied = require_admin()
    if denied:
        return denied
    db = get_db()
    statuses = db.execute('''SELECT s.*, (SELECT COUNT(*) FROM initiatives i WHERE i.status = s.key) AS used
                             FROM statuses s ORDER BY s.sort_order, s.id''').fetchall()
    codes = db.execute('''SELECT c.*, (SELECT COUNT(*) FROM initiatives i WHERE LOWER(i.issue_code) = LOWER(c.name)) AS used
                          FROM issue_codes c ORDER BY c.sort_order, c.id''').fetchall()
    return render_template('lists.html', title='Statuses & issue codes', login=login, statuses=statuses, codes=codes)


@app.route('/lists/status', methods=['POST'])
@app.route('/lists/status/<int:item_id>/<action>', methods=['POST'])
def status_admin(item_id=None, action='save'):
    login, denied = require_admin()
    if denied:
        return denied
    db = get_db()
    if action == 'save':
        label = form_text('label')
        color = form_text('color') if form_text('color') in STATUS_COLORS else 'slate'
        is_done = 1 if request.form.get('is_done') else 0
        if not label:
            flash('Status name cannot be empty.', 'error')
        elif item_id:
            db.execute('UPDATE statuses SET label=?, color=?, is_done=? WHERE id=?', [label, color, is_done, item_id])
            flash('Status "{}" saved.'.format(label), 'success')
        else:
            key = re.sub(r'\s+', ' ', label.lower()).strip()
            if db.execute('SELECT 1 FROM statuses WHERE key = ?', [key]).fetchone():
                flash('Status "{}" already exists.'.format(label), 'error')
            else:
                order = db.execute('SELECT COALESCE(MAX(sort_order), 0) + 1 FROM statuses').fetchone()[0]
                db.execute('INSERT INTO statuses(key, label, color, is_done, sort_order) VALUES (?,?,?,?,?)',
                           [key, label, color, is_done, order])
                flash('Status "{}" added.'.format(label), 'success')
    elif action in ('up', 'down'):
        _reorder(db, 'statuses', item_id, action)
    elif action == 'toggle':
        active = db.execute('SELECT COUNT(*) FROM statuses WHERE is_active').fetchone()[0]
        row = db.execute('SELECT is_active FROM statuses WHERE id = ?', [item_id]).fetchone()
        if row and row['is_active'] and active <= 1:
            flash('At least one status must stay active.', 'error')
        elif row:
            db.execute('UPDATE statuses SET is_active = 1 - is_active WHERE id = ?', [item_id])
    elif action == 'delete':
        row = db.execute('SELECT * FROM statuses WHERE id = ?', [item_id]).fetchone()
        used = db.execute('SELECT COUNT(*) FROM initiatives WHERE status = ?', [row['key']]).fetchone()[0] if row else 0
        if used:
            flash('Status is used by {} initiative(s) – deactivate it instead.'.format(used), 'error')
        elif row:
            db.execute('DELETE FROM statuses WHERE id = ?', [item_id])
            flash('Status deleted.', 'success')
    db.commit()
    return redirect(url_for('lists') + '#statuses')


@app.route('/lists/code', methods=['POST'])
@app.route('/lists/code/<int:item_id>/<action>', methods=['POST'])
def code_admin(item_id=None, action='save'):
    login, denied = require_admin()
    if denied:
        return denied
    db = get_db()
    if action == 'save':
        name = form_text('name')
        if not name:
            flash('Issue code cannot be empty.', 'error')
            return redirect(url_for('lists') + '#codes')
        try:
            if item_id:
                old = db.execute('SELECT name FROM issue_codes WHERE id = ?', [item_id]).fetchone()['name']
                db.execute('UPDATE issue_codes SET name = ? WHERE id = ?', [name, item_id])
                if old != name:  # rename everywhere so initiatives keep their code
                    n = db.execute('UPDATE initiatives SET issue_code = ? WHERE LOWER(issue_code) = LOWER(?)',
                                   [name, old]).rowcount
                    flash('Renamed "{}" to "{}" ({} initiative(s) updated).'.format(old, name, n), 'success')
            else:
                order = db.execute('SELECT COALESCE(MAX(sort_order), 0) + 1 FROM issue_codes').fetchone()[0]
                db.execute('INSERT INTO issue_codes(name, sort_order) VALUES (?,?)', [name, order])
                flash('Issue code "{}" added.'.format(name), 'success')
        except sqlite3.IntegrityError:
            flash('Issue code "{}" already exists.'.format(name), 'error')
    elif action in ('up', 'down'):
        _reorder(db, 'issue_codes', item_id, action)
    elif action == 'toggle':
        db.execute('UPDATE issue_codes SET is_active = 1 - is_active WHERE id = ?', [item_id])
    elif action == 'delete':
        row = db.execute('SELECT name FROM issue_codes WHERE id = ?', [item_id]).fetchone()
        used = db.execute('SELECT COUNT(*) FROM initiatives WHERE LOWER(issue_code) = LOWER(?)',
                          [row['name']]).fetchone()[0] if row else 0
        if used:
            flash('Issue code is used by {} initiative(s) – deactivate it instead.'.format(used), 'error')
        elif row:
            db.execute('DELETE FROM issue_codes WHERE id = ?', [item_id])
            flash('Issue code deleted.', 'success')
    db.commit()
    return redirect(url_for('lists') + '#codes')


# ---------------------------------------------------------------- misc pages

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html', title='Not found', login=current_login()), 404


@app.route('/about')
def about():
    return render_template('about.html', title="About", login=current_login())


@app.route('/login', methods=['GET', 'POST'])
def login():
    login = current_login()
    if request.method == 'GET':
        return render_template('login.html', title="Sign in", active_menu='login', login=login)

    user_name = request.form.get('user_name', '')
    login = UserPass(user_name, request.form.get('user_pass', ''))
    if login.login_user() is not None:
        session['user'] = user_name
        flash('Welcome back, {}!'.format(user_name), 'success')
        return redirect(url_for('initiatives'))

    flash('Invalid user name or password.', 'error')
    return render_template('login.html', title='Sign in', login=login)


@app.route('/logout')
def logout():
    if 'user' in session:
        session.pop('user', None)
        flash('You have been signed out.', 'info')
    return redirect(url_for('initiatives'))


# ---------------------------------------------------------------- users (admin)

@app.route('/users')
def users():
    login, denied = require_admin()
    if denied:
        return denied
    users = get_db().execute('select id, name, full_name, email, is_admin, is_active from users order by full_name collate nocase;').fetchall()
    return render_template('users.html', title="Users", users=users, login=login)


@app.route('/user_status_change/<action>/<user_name>', methods=['POST'])
def user_status_change(action, user_name):
    login, denied = require_admin()
    if denied:
        return denied
    db = get_db()
    if action == 'active':
        db.execute("update users set is_active = (is_active + 1) % 2 where name = ? and name <> ?", [user_name, login.user])
    elif action == 'admin':
        db.execute("update users set is_admin = (is_admin + 1) % 2 where name = ? and name <> ?", [user_name, login.user])
    db.commit()
    return redirect(url_for('users'))


@app.route('/edit_user/<user_name>', methods=['GET', 'POST'])
def edit_user(user_name):
    login, denied = require_admin()
    if denied:
        return denied

    db = get_db()
    user = db.execute('select name, full_name, email from users where name = ?', [user_name]).fetchone()
    if user is None:
        flash('No such user.', 'error')
        return redirect(url_for('users'))

    if request.method == 'GET':
        return render_template('edit_user.html', title="Edit user", user=user, login=login)

    new_email = request.form.get('email', '')
    new_full_name = form_text('full_name')
    new_password = request.form.get('user_pass', '')
    if new_full_name and new_full_name != (user['full_name'] or ''):
        db.execute("update users set full_name = ? where name = ?", [new_full_name, user_name])
        flash('Display name was changed.', 'success')
    if new_email != user['email']:
        db.execute("update users set email = ? where name = ?", [new_email, user_name])
        flash('Email was changed.', 'success')
    if new_password != '':
        db.execute("update users set password = ? where name = ?", [UserPass(user_name, new_password).hash_password(), user_name])
        flash('Password was changed.', 'success')
    db.commit()
    return redirect(url_for('users'))


@app.route('/user_delete/<user_name>', methods=['POST'])
def delete_user(user_name):
    login, denied = require_admin()
    if denied:
        return denied
    db = get_db()
    db.execute('delete from users where name = ? and name <> ?', [user_name, login.user])
    db.commit()
    flash('User {} deleted.'.format(user_name), 'success')
    return redirect(url_for('users'))


@app.route('/new_user', methods=['GET', 'POST'])
def new_user():
    login, denied = require_admin()
    if denied:
        return denied

    db = get_db()
    message = None
    user = {}

    if request.method == 'GET':
        return render_template('new_user.html', title='New user', user=user, login=login)

    user['user_name'] = form_text('user_name')
    user['full_name'] = form_text('full_name')
    user['email'] = form_text('email')
    user['user_pass'] = request.form.get('user_pass', '')

    is_user_name_unique = db.execute('select count(*) as cnt from users where name = ?',
                                     [user['user_name']]).fetchone()['cnt'] == 0
    is_user_email_unique = db.execute('select count(*) as cnt from users where email = ?',
                                      [user['email']]).fetchone()['cnt'] == 0

    if user['user_name'] == '':
        message = 'Name cannot be empty'
    elif user['email'] == '':
        message = 'Email cannot be empty'
    elif user['user_pass'] == '':
        message = 'Password cannot be empty'
    elif not is_user_name_unique:
        message = 'User with the name {} already exists'.format(user['user_name'])
    elif not is_user_email_unique:
        message = 'User with the email {} already exists'.format(user['email'])

    if not message:
        db.execute('''insert into users(name, email, password, is_active, is_admin, full_name)
                      values(?,?,?, True, False, ?);''',
                   [user['user_name'], user['email'], UserPass(user['user_name'], user['user_pass']).hash_password(),
                    user['full_name'] or guess_full_name(user['user_name'])])
        db.commit()
        flash('User {} created.'.format(user['user_name']), 'success')
        return redirect(url_for('users'))

    flash(message, 'error')
    return render_template('new_user.html', title='New user', active_menu='users', user=user, login=login)


ensure_schema()

if __name__ == '__main__':
    app.run(debug=True)
