import os, re, json, time, uuid, shutil, sqlite3, secrets, hashlib, subprocess, signal, threading, resource, zipfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional

import psutil
from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

BASE = Path(__file__).resolve().parent
DATA = Path(os.getenv('DATA_DIR', '/data'))
DATA.mkdir(parents=True, exist_ok=True)
USERS = DATA / 'users'
USERS.mkdir(parents=True, exist_ok=True)
DB = DATA / 'zinhost.db'

ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'loqi')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'loqi')
MAX_TOTAL_BOTS = int(os.getenv('MAX_TOTAL_BOTS', '10'))
DEFAULT_MAX_BOTS = int(os.getenv('DEFAULT_MAX_BOTS', '1'))
DEFAULT_RAM_MB = int(os.getenv('DEFAULT_RAM_MB', '512'))
DEFAULT_DISK_MB = int(os.getenv('DEFAULT_DISK_MB', '1536'))
ALLOWED = {'.py', '.zip'}

app = FastAPI(title='ZINHOST', docs_url='/api/docs')
processes = {}
proc_lock = threading.RLock()


def db():
    c = sqlite3.connect(DB, timeout=30, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
          active INTEGER NOT NULL DEFAULT 1, max_bots INTEGER NOT NULL DEFAULT 1,
          ram_mb INTEGER NOT NULL DEFAULT 512, disk_mb INTEGER NOT NULL DEFAULT 1536,
          plan TEXT NOT NULL DEFAULT 'free', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS bots(
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, name TEXT NOT NULL,
          entry TEXT NOT NULL, auto_restart INTEGER NOT NULL DEFAULT 1,
          status TEXT NOT NULL DEFAULT 'stopped', created_at TEXT NOT NULL,
          UNIQUE(user_id, name)
        );
        ''')
        row = c.execute('SELECT id FROM users WHERE username=?', (ADMIN_USERNAME,)).fetchone()
        if not row:
            c.execute('INSERT INTO users(username,password_hash,role,max_bots,ram_mb,disk_mb,plan,created_at) VALUES(?,?,?,?,?,?,?,?)',
                      (ADMIN_USERNAME, hash_pw(ADMIN_PASSWORD), 'admin', 999, 4096, 10240, 'admin', now()))
        c.commit()


def now(): return datetime.now(timezone.utc).isoformat()

def hash_pw(pw: str) -> str:
    salt = secrets.token_bytes(16)
    return 'pbkdf2$' + salt.hex() + '$' + hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 210000).hex()

def check_pw(pw: str, stored: str) -> bool:
    try:
        _, salt, digest = stored.split('$')
        got = hashlib.pbkdf2_hmac('sha256', pw.encode(), bytes.fromhex(salt), 210000).hex()
        return secrets.compare_digest(got, digest)
    except Exception: return False

def user_dir(uid):
    p = USERS / str(uid); p.mkdir(parents=True, exist_ok=True); return p

def safe_name(name):
    name = Path(name or '').name
    if not name or name in {'.','..'} or not re.fullmatch(r'[A-Za-z0-9._-]{1,120}', name):
        raise HTTPException(400, 'Invalid filename')
    if Path(name).suffix.lower() not in ALLOWED:
        raise HTTPException(400, 'Only .py and .zip uploads are allowed')
    return name

def disk_usage(uid):
    p = user_dir(uid)
    return sum(x.stat().st_size for x in p.rglob('*') if x.is_file())

def row_user(row):
    return {k: row[k] for k in row.keys()}

def auth(request: Request):
    token = request.headers.get('Authorization','').removeprefix('Bearer ').strip() or request.cookies.get('zh_session')
    if not token: raise HTTPException(401, 'Login required')
    with db() as c:
        r = c.execute('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>? AND u.active=1', (token, now())).fetchone()
    if not r: raise HTTPException(401, 'Session expired')
    return r

def admin(user=Depends(auth)):
    if user['role'] != 'admin': raise HTTPException(403, 'Admin only')
    return user

def proc_key(uid,bid): return f'{uid}:{bid}'

def bot_user_limit(uid,key):
    with db() as c: r=c.execute('SELECT '+key+' FROM users WHERE id=?',(uid,)).fetchone()
    return int(r[key]) if r else DEFAULT_RAM_MB

def get_bot(uid,bid):
    with db() as c:
        r=c.execute('SELECT * FROM bots WHERE id=? AND user_id=?',(bid,uid)).fetchone()
    if not r: raise HTTPException(404,'Bot not found')
    return r

def resolve_entry(folder: Path, entry: str):
    p=(folder / entry).resolve()
    if folder.resolve() not in p.parents or not p.exists(): raise HTTPException(400,'Invalid entry file')
    return p

def start_process(bot):
    uid, bid = bot['user_id'], bot['id']; key=proc_key(uid,bid)
    with proc_lock:
        p=processes.get(key)
        if p and p.poll() is None: return
        folder=user_dir(uid)
        entry=resolve_entry(folder, bot['entry'])
        if entry.suffix.lower()!='.py': raise HTTPException(400,'Only Python entrypoints are enabled in this build')
        log=folder/f'{bid}.log'
        f=open(log,'a',encoding='utf-8',errors='ignore')
        f.write(f'\\n[{now()}] starting {entry.name}\\n'); f.flush()
        env=os.environ.copy(); env['ZINHOST_USER_ID']=str(uid); env['ZINHOST_BOT_ID']=str(bid)
        running=sum(1 for x in processes.values() if x[0].poll() is None)
        if running >= MAX_TOTAL_BOTS: raise HTTPException(503,'Platform bot capacity is full')
        ram_limit=int(bot_user_limit(uid,'ram_mb')*1024*1024)
        def limits():
            try: resource.setrlimit(resource.RLIMIT_AS,(ram_limit,ram_limit))
            except Exception: pass
        p=subprocess.Popen(['python',str(entry)],cwd=folder,stdin=subprocess.PIPE,stdout=f,stderr=subprocess.STDOUT,env=env,start_new_session=True,text=True,preexec_fn=limits if os.name=='posix' else None)
        processes[key]=(p,f,time.time())
        with db() as c: c.execute('UPDATE bots SET status=? WHERE id=?',('running',bid)); c.commit()

def stop_process(uid,bid):
    key=proc_key(uid,bid)
    with proc_lock:
        item=processes.get(key)
        if item:
            p,f,_=item
            try:
                os.killpg(p.pid, signal.SIGTERM)
                try: p.wait(timeout=3)
                except subprocess.TimeoutExpired: os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            except Exception:
                try: p.kill()
                except Exception: pass
            try: f.close()
            except Exception: pass
            processes.pop(key,None)
        with db() as c: c.execute('UPDATE bots SET status=? WHERE id=?',('stopped',bid)); c.commit()

def monitor():
    while True:
        time.sleep(2)
        with proc_lock:
            for key,item in list(processes.items()):
                p,f,_=item
                if p.poll() is None:
                    try:
                        uid,bid=map(int,key.split(':'))
                        limit=bot_user_limit(uid,'ram_mb')*1024*1024
                        rss=psutil.Process(p.pid).memory_info().rss
                        if rss>limit:
                            f.write(f'\n[{now()}] memory limit exceeded ({rss} > {limit}); stopping.\n'); f.flush()
                            stop_process(uid,bid)
                            continue
                    except Exception: pass
                if p.poll() is not None:
                    try: f.close()
                    except Exception: pass
                    processes.pop(key,None)
                    uid,bid=map(int,key.split(':'))
                    with db() as c:
                        r=c.execute('SELECT auto_restart FROM bots WHERE id=?',(bid,)).fetchone()
                        c.execute('UPDATE bots SET status=? WHERE id=?',('stopped',bid)); c.commit()
                    if r and r['auto_restart']:
                        try: start_process(get_bot(uid,bid))
                        except Exception: pass
threading.Thread(target=monitor,daemon=True).start()

init_db()

@app.get('/health')
def health(): return {'ok':True,'service':'zinhost'}

@app.post('/api/auth/register')
def register(username: str=Form(...), password: str=Form(...)):
    username=username.strip().lower()
    if not re.fullmatch(r'[a-z0-9_]{3,32}', username): raise HTTPException(400,'Username must be 3-32 chars: letters, numbers, underscore')
    if len(password)<6: raise HTTPException(400,'Password must be at least 6 characters')
    with db() as c:
        try:
            c.execute('INSERT INTO users(username,password_hash,max_bots,ram_mb,disk_mb,created_at) VALUES(?,?,?,?,?,?)',(username,hash_pw(password),DEFAULT_MAX_BOTS,DEFAULT_RAM_MB,DEFAULT_DISK_MB,now())); c.commit()
        except sqlite3.IntegrityError: raise HTTPException(409,'Username already exists')
    return {'ok':True}

@app.post('/api/auth/login')
def login(username: str=Form(...), password: str=Form(...), remember: bool=Form(False)):
    with db() as c: r=c.execute('SELECT * FROM users WHERE username=?',(username.strip().lower(),)).fetchone()
    if not r or not r['active'] or not check_pw(password,r['password_hash']): raise HTTPException(401,'Invalid username or password')
    token=secrets.token_urlsafe(32); days=30 if remember else 1
    exp=(datetime.now(timezone.utc)+timedelta(days=days)).isoformat()
    with db() as c: c.execute('INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)',(token,r['id'],exp)); c.commit()
    return {'token':token,'user':row_user(r)}

@app.post('/api/auth/logout')
def logout(request:Request,user=Depends(auth)):
    token=request.headers.get('Authorization','').removeprefix('Bearer ').strip()
    with db() as c: c.execute('DELETE FROM sessions WHERE token=?',(token,)); c.commit()
    return {'ok':True}

@app.get('/api/me')
def me(user=Depends(auth)): return {'user':row_user(user),'disk_used':disk_usage(user['id'])}

@app.get('/api/bots')
def bots(user=Depends(auth)):
    with db() as c: rows=c.execute('SELECT * FROM bots WHERE user_id=? ORDER BY id DESC',(user['id'],)).fetchall()
    out=[]
    for r in rows:
        d=row_user(r); item=process_stats(r); d.update(item); out.append(d)
    return out

def process_stats(r):
    key=proc_key(r['user_id'],r['id']); item=processes.get(key); base={'cpu':0,'ram':0,'pid':None}
    if not item:return base
    p=item[0]
    try:
        pr=psutil.Process(p.pid); base.update(cpu=pr.cpu_percent(interval=0),ram=pr.memory_info().rss,pid=p.pid)
    except Exception: pass
    return base

@app.post('/api/bots')
def create_bot(name:str=Form(...),entry:str=Form('main.py'),user=Depends(auth)):
    name=re.sub(r'[^a-zA-Z0-9_-]','-',name.strip())[:40]
    if not name: raise HTTPException(400,'Invalid bot name')
    with db() as c:
        count=c.execute('SELECT COUNT(*) n FROM bots WHERE user_id=?',(user['id'],)).fetchone()['n']
        if count>=user['max_bots']: raise HTTPException(403,f'Bot slot limit reached ({user["max_bots"]})')
        try:
            c.execute('INSERT INTO bots(user_id,name,entry,created_at) VALUES(?,?,?,?)',(user['id'],name,entry,now())); c.commit()
        except sqlite3.IntegrityError: raise HTTPException(409,'Bot name already exists')
        bid=c.execute('SELECT last_insert_rowid()').fetchone()[0]
    return {'ok':True,'id':bid}

@app.post('/api/bots/{bid}/start')
def start_bot(bid:int,user=Depends(auth)):
    bot=get_bot(user['id'],bid); start_process(bot); return {'ok':True}

@app.post('/api/bots/{bid}/stop')
def stop_bot(bid:int,user=Depends(auth)):
    get_bot(user['id'],bid); stop_process(user['id'],bid); return {'ok':True}

@app.post('/api/bots/{bid}/restart')
def restart_bot(bid:int,user=Depends(auth)):
    get_bot(user['id'],bid); stop_process(user['id'],bid); start_process(get_bot(user['id'],bid)); return {'ok':True}

@app.delete('/api/bots/{bid}')
def delete_bot(bid:int,user=Depends(auth)):
    bot=get_bot(user['id'],bid); stop_process(user['id'],bid)
    with db() as c: c.execute('DELETE FROM bots WHERE id=?',(bid,)); c.commit()
    (user_dir(user['id'])/f'{bid}.log').unlink(missing_ok=True)
    return {'ok':True}

@app.post('/api/bots/{bid}/stdin')
def stdin_bot(bid:int,text:str=Form(...),user=Depends(auth)):
    get_bot(user['id'],bid); item=processes.get(proc_key(user['id'],bid))
    if not item or item[0].poll() is not None: raise HTTPException(409,'Bot is not running')
    try: item[0].stdin.write(text+'\\n'); item[0].stdin.flush()
    except Exception as e: raise HTTPException(500,str(e))
    return {'ok':True}

@app.post('/api/bots/{bid}/autorestart')
def autorestart(bid:int,enabled:bool=Form(...),user=Depends(auth)):
    get_bot(user['id'],bid)
    with db() as c:c.execute('UPDATE bots SET auto_restart=? WHERE id=?',(int(enabled),bid));c.commit()
    return {'ok':True}

@app.get('/api/bots/{bid}/logs')
def logs(bid:int,user=Depends(auth)):
    get_bot(user['id'],bid); p=user_dir(user['id'])/f'{bid}.log'
    text=p.read_text(encoding='utf-8',errors='ignore') if p.exists() else ''
    return {'logs':text[-20000:]}

@app.post('/api/files/upload')
async def upload(file:UploadFile=File(...),user=Depends(auth)):
    name=safe_name(file.filename)
    data=await file.read()
    if disk_usage(user['id'])+len(data)>user['disk_mb']*1024*1024: raise HTTPException(413,'Disk quota exceeded')
    dest=user_dir(user['id'])/name; dest.write_bytes(data)
    created_bot=None
    # Uploading a Python file immediately creates and starts its server.
    if dest.suffix.lower()=='.py':
        with db() as c:
            count=c.execute('SELECT COUNT(*) n FROM bots WHERE user_id=?',(user['id'],)).fetchone()['n']
            if count < user['max_bots']:
                base=re.sub(r'[^a-zA-Z0-9_-]','-',dest.stem)[:40] or 'bot'
                bot_name=base; i=2
                while c.execute('SELECT 1 FROM bots WHERE user_id=? AND name=?',(user['id'],bot_name)).fetchone():
                    suffix=f'-{i}'; bot_name=(base[:40-len(suffix)]+suffix); i+=1
                c.execute('INSERT INTO bots(user_id,name,entry,created_at) VALUES(?,?,?,?)',(user['id'],bot_name,name,now()))
                c.commit(); bid=c.execute('SELECT last_insert_rowid()').fetchone()[0]
                created_bot={'id':bid,'name':bot_name,'entry':name}
        if created_bot:
            try: start_process(get_bot(user['id'],created_bot['id']))
            except Exception as e: created_bot['start_error']=str(e)
    return {'ok':True,'name':name,'size':len(data),'bot':created_bot}

@app.get('/api/files')
def files(user=Depends(auth)):
    out=[]
    for p in user_dir(user['id']).iterdir():
        if p.is_file() and p.suffix.lower() in ALLOWED: out.append({'name':p.name,'size':p.stat().st_size,'modified':p.stat().st_mtime})
    return sorted(out,key=lambda x:x['name'].lower())

@app.get('/api/files/download')
def download(name:str,user=Depends(auth)):
    name=safe_name(name); p=user_dir(user['id'])/name
    if not p.exists(): raise HTTPException(404,'File not found')
    return FileResponse(p,filename=name)

@app.delete('/api/files')
def delete_file(name:str,user=Depends(auth)):
    name=safe_name(name); p=user_dir(user['id'])/name
    if not p.exists(): raise HTTPException(404,'File not found')
    p.unlink(); return {'ok':True}

# Admin
@app.get('/api/admin/overview')
def admin_overview(user=Depends(admin)):
    with db() as c:
        users=c.execute('SELECT * FROM users ORDER BY id DESC').fetchall(); bots=c.execute('SELECT * FROM bots ORDER BY id DESC').fetchall()
    running=sum(1 for b in bots if proc_key(b['user_id'],b['id']) in processes and processes[proc_key(b['user_id'],b['id'])][0].poll() is None)
    return {'users':[row_user(u) for u in users], 'bots':[row_user(b) for b in bots], 'running':running, 'max_total_bots':MAX_TOTAL_BOTS}

@app.patch('/api/admin/users/{uid}')
def admin_user(uid:int, max_bots:Optional[int]=Form(None),ram_mb:Optional[int]=Form(None),disk_mb:Optional[int]=Form(None),plan:Optional[str]=Form(None),active:Optional[bool]=Form(None),user=Depends(admin)):
    fields=[]; vals=[]
    for k,v in [('max_bots',max_bots),('ram_mb',ram_mb),('disk_mb',disk_mb),('plan',plan),('active',active)]:
        if v is not None: fields.append(k+'=?'); vals.append(int(v) if isinstance(v,bool) else v)
    if not fields: raise HTTPException(400,'No changes')
    vals.append(uid)
    with db() as c:c.execute('UPDATE users SET '+','.join(fields)+' WHERE id=?',vals);c.commit()
    return {'ok':True}

@app.delete('/api/admin/users/{uid}')
def admin_delete(uid:int,user=Depends(admin)):
    if uid==user['id']: raise HTTPException(400,'Cannot delete yourself')
    with db() as c: bots=c.execute('SELECT id FROM bots WHERE user_id=?',(uid,)).fetchall()
    for b in bots: stop_process(uid,b['id'])
    with db() as c:c.execute('DELETE FROM bots WHERE user_id=?',(uid,));c.execute('DELETE FROM users WHERE id=?',(uid,));c.commit()
    shutil.rmtree(user_dir(uid),ignore_errors=True)
    return {'ok':True}

@app.get('/api/admin/users/{uid}/files')
def admin_files(uid:int,user=Depends(admin)):
    with db() as c:
        if not c.execute('SELECT id FROM users WHERE id=?',(uid,)).fetchone(): raise HTTPException(404,'User not found')
    out=[]
    for p in user_dir(uid).iterdir():
        if p.is_file(): out.append({'name':p.name,'size':p.stat().st_size})
    return out

@app.get('/api/admin/users/{uid}/files/download')
def admin_download(uid:int,name:str,user=Depends(admin)):
    name=safe_name(name); p=user_dir(uid)/name
    if not p.exists(): raise HTTPException(404,'File not found')
    return FileResponse(p,filename=name)

@app.post('/api/admin/bots/{bid}/start')
def admin_start_bot(bid:int,user=Depends(admin)):
    with db() as c:r=c.execute('SELECT * FROM bots WHERE id=?',(bid,)).fetchone()
    if not r: raise HTTPException(404,'Bot not found')
    start_process(r); return {'ok':True}

@app.post('/api/admin/bots/{bid}/stop')
def admin_stop_bot(bid:int,user=Depends(admin)):
    with db() as c:r=c.execute('SELECT * FROM bots WHERE id=?',(bid,)).fetchone()
    if not r: raise HTTPException(404,'Bot not found')
    stop_process(r['user_id'],bid); return {'ok':True}

app.mount('/', StaticFiles(directory=str(BASE/'static'),html=True),name='static')
