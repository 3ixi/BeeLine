from fastapi import FastAPI, Request, Depends, HTTPException, status, UploadFile, File, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool
import uvicorn
import os
import re
import tarfile
import tempfile
import shutil
import json
import sys
import time
from datetime import datetime, timedelta
from typing import Optional, List
import secrets
import subprocess
import threading
import croniter
from typing_extensions import Annotated
from scheduler import (
    init_scheduler,
    add_job,
    remove_job,
    shutdown_scheduler,
    reload_jobs,
    is_task_running,
    list_running_tasks,
    stop_task as stop_task_process,
    env_vars,
    run_script as execute_task_script,
    validate_cron_expression,
    scheduler as scheduler_instance,
)
import maintenance
from maintenance import (
    db_stats,
    run_cleanup,
    save_settings as save_app_settings,
    settings_for_ui,
    vacuum as vacuum_db,
)
from contextlib import asynccontextmanager

from passlib.context import CryptContext
from models import SessionLocal, Script, Task, TaskLog, User, EnvironmentVariable, Session, ScriptFile

# 创建密码哈希的上下文
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 定义当前版本
CURRENT_VERSION = "1.0.9"

# 创建必要的目录
os.makedirs("static", exist_ok=True)
os.makedirs("templates", exist_ok=True)
os.makedirs("scripts", exist_ok=True)

# 脚本根目录（绝对路径，所有文件操作都以它为边界）
SCRIPTS_DIR = os.path.abspath("scripts")

# 单文件上传体积上限（MB），可通过环境变量覆盖
MAX_UPLOAD_MB = int(os.environ.get("BEELINE_MAX_UPLOAD_MB", "200"))

# 登录失败限速：同一来源 5 次失败后锁定 5 分钟
LOGIN_MAX_FAILURES = 5
LOGIN_LOCK_SECONDS = 300
_login_attempts = {}
_login_lock = threading.Lock()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _check_login_allowed(key: str):
    """返回 (是否允许登录, 剩余锁定秒数)。"""
    with _login_lock:
        record = _login_attempts.get(key)
        if not record:
            return True, 0
        count, first_at = record
        if time.time() - first_at > LOGIN_LOCK_SECONDS:
            _login_attempts.pop(key, None)
            return True, 0
        if count >= LOGIN_MAX_FAILURES:
            return False, int(LOGIN_LOCK_SECONDS - (time.time() - first_at)) + 1
        return True, 0


def _record_login_failure(key: str):
    with _login_lock:
        count, first_at = _login_attempts.get(key, (0, time.time()))
        if time.time() - first_at > LOGIN_LOCK_SECONDS:
            count, first_at = 0, time.time()
        _login_attempts[key] = (count + 1, first_at)
        # 简单裁剪，避免字典无限增长
        if len(_login_attempts) > 5000:
            _login_attempts.clear()


def _reset_login_failures(key: str):
    with _login_lock:
        _login_attempts.pop(key, None)


_UNSAFE_NAME_CHARS = re.compile(r'[\\/:*?"<>|\x00-\x1f]')
# pip 包名与版本号白名单：仅允许常规字符，杜绝 "--index-url" 之类的参数注入
_PACKAGE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
_PACKAGE_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+!-]{0,49}")
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def safe_join(base: str, *paths: str) -> str:
    """把相对路径安全地拼接到 base 下，越界直接拒绝。

    使用 realpath + 分隔符后缀比较，避免 abspath 前缀匹配被 `scripts_evil/` 之类的同级目录绕过。
    """
    base_abs = os.path.realpath(base)
    target = os.path.realpath(os.path.join(base_abs, *paths))
    if target != base_abs and not target.startswith(base_abs + os.sep):
        raise HTTPException(status_code=400, detail="非法的文件路径")
    return target


def sanitize_filename(filename: str) -> str:
    """提取纯文件名并校验，拒绝路径分隔符、穿越片段与保留名。"""
    if not filename:
        raise HTTPException(status_code=400, detail="文件名不能为空")
    name = filename.replace("\\", "/").split("/")[-1].strip()
    if name in ("", ".", ".."):
        raise HTTPException(status_code=400, detail="文件名不合法")
    if _UNSAFE_NAME_CHARS.search(name):
        raise HTTPException(status_code=400, detail="文件名包含非法字符")
    if os.path.splitext(name)[0].upper() in _WINDOWS_RESERVED:
        raise HTTPException(status_code=400, detail="文件名不能使用系统保留名")
    if len(name) > 120:
        raise HTTPException(status_code=400, detail="文件名过长")
    return name


async def save_upload(file: UploadFile, dest_path: str) -> int:
    """流式保存上传文件，超限即中断并清理临时文件。"""
    max_bytes = MAX_UPLOAD_MB * 1024 * 1024
    tmp_path = dest_path + ".uploading"
    total = 0
    try:
        with open(tmp_path, "wb") as buffer:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if max_bytes and total > max_bytes:
                    raise HTTPException(status_code=413, detail=f"文件超过 {MAX_UPLOAD_MB} MB 上限")
                buffer.write(chunk)
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise
    os.replace(tmp_path, dest_path)
    return total


def safe_extract_tar(tar: tarfile.TarFile, dest: str):
    """安全解包：拒绝绝对路径、父目录穿越、符号/硬链接与设备文件。"""
    dest_abs = os.path.realpath(dest)
    for member in tar.getmembers():
        name = member.name
        normalized = name.replace("\\", "/")
        if normalized.startswith("/") or os.path.isabs(name):
            raise HTTPException(status_code=400, detail="备份包包含绝对路径，已拒绝导入")
        if ".." in normalized.split("/"):
            raise HTTPException(status_code=400, detail="备份包包含目录穿越路径，已拒绝导入")
        if member.issym() or member.islnk() or member.isdev():
            raise HTTPException(status_code=400, detail="备份包包含链接或设备文件，已拒绝导入")
        target = os.path.realpath(os.path.join(dest_abs, name))
        if target != dest_abs and not target.startswith(dest_abs + os.sep):
            raise HTTPException(status_code=400, detail="备份包包含越界路径，已拒绝导入")
    if hasattr(tarfile, "data_filter"):
        tar.extractall(dest, filter="data")
    else:
        tar.extractall(dest)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时执行
    db = SessionLocal()
    startup_default_password = False
    try:
        # 检查是否存在任何用户
        user_count = db.query(User).count()
        if user_count == 0:
            # 没有找到用户，创建默认的管理员用户
            default_username = "admin"
            default_password = os.environ.get("DEFAULT_ADMIN_PASSWORD", "admin")
            startup_default_password = "DEFAULT_ADMIN_PASSWORD" not in os.environ
            hashed_password = get_password_hash(default_password)
            default_user = User(username=default_username, hashed_password=hashed_password)
            db.add(default_user)
            db.commit()
            print(f"默认管理员用户 '{default_username}' 已创建。")
            if startup_default_password:
                print("[警告] 当前使用默认口令 admin/admin，请在“系统设置”中立即修改密码。")
        else:
            print(f"在数据库中找到 {user_count} 个用户。没有创建默认用户。")

        # 加载环境变量（写入 scheduler.env_vars，任务执行时直接读取同一份字典）
        env_vars.clear()
        db_env_vars = db.query(EnvironmentVariable).all()
        for env_var in db_env_vars:
            env_vars[env_var.key] = env_var.value
        print(f"从数据库加载了 {len(env_vars)} 个环境变量。")

        # 初始化调度器
        init_scheduler()
    except Exception as e:
        print(f"启动时出错: {e}")
    finally:
        db.close()

    # 存储层迁移（WAL / 增量回收 / 索引）可能需要压缩大库，放到后台线程避免阻塞启动
    def _prepare_storage():
        try:
            maintenance.ensure_storage()
        except Exception as exc:
            print(f"[maintenance] 后台存储初始化异常: {exc}")

    threading.Thread(target=_prepare_storage, name="beeline-storage-init", daemon=True).start()

    yield

    # 关闭时执行
    shutdown_scheduler()


app = FastAPI(title="BeeLine Web Controller", lifespan=lifespan)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response



# 挂载静态文件
app.mount("/static", StaticFiles(directory="static"), name="static")

# 设置模板
templates = Jinja2Templates(directory="templates")


def validate_script_filename(filename):
    """验证脚本文件名是否合法

    Args:
        filename: 要验证的文件名

    Returns:
        tuple: (是否合法, 错误信息/处理后的文件名)
    """
    try:
        name = sanitize_filename(filename)
    except HTTPException as exc:
        return False, str(exc.detail)
    if ' ' in name:
        return False, "文件名不能包含空格"
    if name.startswith('.'):
        return False, "文件名不能以点开头"
    if not name.endswith('.py'):
        name += '.py'
    return True, name


async def read_json_body(request: Request) -> dict:
    """解析 JSON 请求体，格式错误时返回 400 而不是 500。"""
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="请求格式错误，需要 JSON 请求体")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="请求格式错误，需要 JSON 对象")
    return data


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(request: Request, db = Depends(get_db)) -> Optional[str]:
    session_id = request.cookies.get("session_id")
    if session_id:
        session = db.query(Session).filter(Session.id == session_id).first()
        if session and datetime.now() < session.expires:
            return session.username
        elif session:
            db.delete(session)
            db.commit()
    return None

# 验证密码的辅助函数
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# 获取密码哈希的辅助函数
def get_password_hash(password):
    return pwd_context.hash(password)

@app.get("/", response_class=HTMLResponse)
async def root(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if user:
        # 获取 Python 版本
        python_version = sys.version.split()[0]
        
        # 获取最近的任务日志（例如，最后 10 条日志）
        recent_logs = db.query(TaskLog).order_by(TaskLog.started_at.desc()).limit(10).all()

        # 获取脚本总数和任务总数
        script_count = db.query(Script).count()
        task_count = db.query(Task).count()

        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "username": user,
                "python_version": python_version,
                "recent_logs": recent_logs, # 传递最近日志到模板
                "script_count": script_count, # 传递脚本总数
                "task_count": task_count # 传递任务总数
            }
        )
    return templates.TemplateResponse(
        "login.html",
        {"request": request}
    )

@app.post("/login")
async def login(request: Request, db=Depends(get_db)):
    form_data = await request.form()
    username = (form_data.get("username") or "").strip()
    password = form_data.get("password") or ""

    client_key = _client_ip(request)
    allowed, remaining = _check_login_allowed(client_key)
    if not allowed:
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": f"登录失败次数过多，请在 {remaining // 60 + 1} 分钟后重试",
            },
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    # 在数据库中查找用户
    user = db.query(User).filter(User.username == username).first()

    if user and verify_password(password, user.hashed_password):
        _reset_login_failures(client_key)
        session_id = secrets.token_urlsafe(32)
        # 在数据库中存储会话
        new_session = Session(
            id=session_id,
            username=user.username,
            expires=datetime.now() + timedelta(days=7)
        )
        db.add(new_session)
        # 顺带清理该用户的过期会话，避免 sessions 表无限增长
        db.query(Session).filter(Session.username == user.username, Session.expires < datetime.now()).delete()
        db.commit()

        response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
        response.set_cookie(
            key="session_id",
            value=session_id,
            max_age=7 * 24 * 3600,
            httponly=True,
            samesite="lax",
            secure=request.url.scheme == "https",
        )
        return response

    _record_login_failure(client_key)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "无效的凭据"}
    )

@app.get("/logout")
async def logout(request: Request, db=Depends(get_db)):
    session_id = request.cookies.get("session_id")
    if session_id:
        # 从数据库中删除会话
        session = db.query(Session).filter(Session.id == session_id).first()
        if session:
            db.delete(session)
            db.commit()

    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("session_id")
    return response

# 系统设置
@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    # 从数据库获取当前用户以潜在地显示用户名（可选）
    current_user_db = db.query(User).filter(User.username == user).first()
    if not current_user_db:
         # 如果 get_current_user 正常工作，不应发生这种情况，但防御性地处理
         return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)


    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "username": user,
            "current_username": current_user_db.username, # 将当前用户名传递给模板
            "cleanup": settings_for_ui(),
        }
    )

@app.post("/settings")
async def update_settings(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    form_data = await request.form()
    new_username = form_data.get("new_username")
    current_password = form_data.get("current_password")
    new_password = form_data.get("new_password")
    confirm_password = form_data.get("confirm_password")

    current_user_db = db.query(User).filter(User.username == user).first()
    if not current_user_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    def render_settings(**extra):
        """统一渲染设置页，保证清理策略等上下文在任一分支都不缺失。"""
        context = {
            "request": request,
            "username": user,
            "current_username": current_user_db.username,
            "cleanup": settings_for_ui(),
        }
        context.update(extra)
        return templates.TemplateResponse("settings.html", context)

    # 验证当前密码
    if not verify_password(current_password or "", current_user_db.hashed_password):
        return render_settings(error="当前密码不正确")

    # 如果提供了新用户名且不同，则更新用户名
    if new_username and new_username != current_user_db.username:
        existing_user = db.query(User).filter(User.username == new_username).first()
        if existing_user:
            return render_settings(error="新用户名已存在")
        current_user_db.username = new_username
        # 同步更新该用户名下所有会话
        db.query(Session).filter(Session.username == user).update({"username": new_username})
        db.commit()
        user = new_username

    # 如果提供了新密码，则更新密码
    if new_password:
        if new_password != confirm_password:
            return render_settings(error="新密码和确认密码不匹配")
        current_user_db.hashed_password = get_password_hash(new_password)

    db.commit()

    return render_settings(message="设置已更新成功")

# 数据维护：自动清理与空间回收
@app.get("/api/maintenance/status")
async def maintenance_status(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")
    return JSONResponse({
        "busy": maintenance.MAINTENANCE_LOCK.locked(),
        "stats": db_stats(),
        "settings": settings_for_ui(),
    })


@app.post("/api/maintenance/settings")
async def update_maintenance_settings(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    try:
        data = await read_json_body(request)
    except Exception:
        raise HTTPException(status_code=400, detail="请求格式错误")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="请求格式错误")

    try:
        save_app_settings(data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # 配置变化后立即重建每日清理任务
    maintenance.register_cleanup_job(scheduler_instance)
    return JSONResponse({"message": "清理策略已保存", "settings": settings_for_ui()})


@app.post("/api/maintenance/cleanup")
async def maintenance_cleanup(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")
    if maintenance.MAINTENANCE_LOCK.locked():
        return JSONResponse({"message": "维护任务正在执行，请稍后刷新"}, status_code=409)

    vacuum_after = True
    try:
        payload = await request.json()
        if isinstance(payload, dict) and payload.get("vacuum") is not None:
            vacuum_after = bool(payload.get("vacuum"))
    except Exception:
        pass

    threading.Thread(
        target=run_cleanup,
        kwargs={"trigger": "manual", "vacuum_after": vacuum_after},
        name="beeline-cleanup",
        daemon=True,
    ).start()
    return JSONResponse({"message": "清理任务已开始执行"})


@app.post("/api/maintenance/vacuum")
async def maintenance_vacuum(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")
    if maintenance.MAINTENANCE_LOCK.locked():
        return JSONResponse({"message": "维护任务正在执行，请稍后刷新"}, status_code=409)

    threading.Thread(target=vacuum_db, name="beeline-vacuum", daemon=True).start()
    return JSONResponse({"message": "空间回收已开始执行"})


# 环境变量管理
@app.get("/env", response_class=HTMLResponse)
async def list_env_vars(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    # 从数据库获取环境变量
    env_vars = db.query(EnvironmentVariable).all()
    # 转换为字典格式，包含创建时间
    env_vars_dict = {var.key: var for var in env_vars}

    return templates.TemplateResponse(
        "env.html",
        {
            "request": request,
            "username": user,
            "env_vars": env_vars_dict
        }
    )

@app.post("/env")
async def set_env_var(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    data = await read_json_body(request)
    key = data.get("key")
    value = data.get("value")

    if not key:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="变量名不能为空")

    # 检查变量是否已存在
    existing_var = db.query(EnvironmentVariable).filter(EnvironmentVariable.key == key).first()
    if existing_var:
        # 更新现有变量
        existing_var.value = value
        existing_var.created_at = datetime.now() # 更新创建时间
    else:
        # 创建新变量
        new_var = EnvironmentVariable(key=key, value=value)
        db.add(new_var)

    db.commit()
    # 更新内存中的环境变量
    global env_vars
    env_vars[key] = value

    return JSONResponse({"message": "环境变量已设置"})

@app.get("/env/{key}")
async def get_env_var(key: str, request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    env_var = db.query(EnvironmentVariable).filter(EnvironmentVariable.key == key).first()
    if not env_var:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="环境变量未找到")

    # 返回环境变量的详细信息，包括值和创建时间
    return {
        "key": env_var.key,
        "value": env_var.value,
        "created_at": env_var.created_at.strftime('%Y-%m-%d %H:%M:%S') if env_var.created_at else None
    }

@app.delete("/env/{key}")
async def delete_env_var(key: str, request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    # 从数据库中删除
    db_env_var = db.query(EnvironmentVariable).filter(EnvironmentVariable.key == key).first()
    if db_env_var:
        db.delete(db_env_var)
        db.commit()

    # 从内存中删除
    global env_vars
    if key in env_vars:
        del env_vars[key]

    return JSONResponse({"message": "环境变量已删除"})

# 包管理
@app.get("/packages", response_class=HTMLResponse)
async def list_packages(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse(
        "packages.html",
        {
            "request": request,
            "username": user
        }
    )

@app.get("/api/packages")
async def search_packages(request: Request, search: str = "", db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    try:
        # 使用 subprocess 运行 pip list 命令并获取 JSON 输出
        result = subprocess.run(
            [sys.executable or "python", "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=120,
            check=True
        )
        packages = json.loads(result.stdout)
        
        # 如果提供了搜索词，过滤包列表
        if search:
            search = search.lower()
            packages = [p for p in packages if search in p["name"].lower()]
            
        package_count = len(packages)
        
        return {
            "packages": packages,
            "package_count": package_count
        }
    except subprocess.CalledProcessError as e:
        print(f"列出包时出错: {e}")
        return {"packages": [], "package_count": 0}
    except json.JSONDecodeError as e:
        print(f"解码 pip list 输出时出错: {e}")
        return {"packages": [], "package_count": 0}

@app.post("/packages")
async def install_package(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    try:
        data = await read_json_body(request)
        package_name = data.get("name")
        package_version = data.get("version")

        if not package_name:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="包名不能为空")

        # 严格校验包名与版本号，防止通过 --index-url 之类的参数注入替换安装源
        package_name = str(package_name).strip()
        if not _PACKAGE_NAME_RE.fullmatch(package_name):
            raise HTTPException(status_code=400, detail="包名不合法")
        if package_version:
            package_version = str(package_version).strip()
            if not _PACKAGE_VERSION_RE.fullmatch(package_version):
                raise HTTPException(status_code=400, detail="版本号不合法")

        spec = f"{package_name}=={package_version}" if package_version else package_name
        python_exe = sys.executable or "python"
        process = subprocess.run(
            [
                python_exe, "-m", "pip", "install",
                "--no-input",
                "--disable-pip-version-check",
                spec,
            ],
            capture_output=True,
            text=True,
            timeout=600,
            check=True
        )

        return JSONResponse({"message": f"包 {spec} 安装成功", "output": process.stdout})

    except HTTPException:
        raise
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="安装超时（10 分钟），请检查网络或稍后重试")
    except subprocess.CalledProcessError as e:
        print(f"安装包时出错: {e.stderr}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"安装失败: {e.stderr}")
    except Exception as e:
        print(f"安装包时发生未知错误: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"安装失败: {e}")

# 日志管理
@app.get("/logs", response_class=HTMLResponse)
async def list_logs(request: Request, db=Depends(get_db), task_id: Optional[int] = None, page: int = 1, per_page: int = 15, only_errors: Optional[str] = None):
    user = get_current_user(request, db=db)
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    # 限制单页条数，避免 per_page 被构造为超大值导致全表加载
    per_page = max(1, min(int(per_page or 15), 200))

    try:
        # 构建基础查询
        query = db.query(TaskLog).order_by(TaskLog.started_at.desc())
        if task_id is not None:
            query = query.filter(TaskLog.task_id == task_id)
            
        # 只看报错筛选
        if only_errors == 'true':
            query = query.filter(TaskLog.status == 'failed')
        
        # 计算总记录数
        total_count = query.count()
        
        # 计算总页数
        total_pages = (total_count + per_page - 1) // per_page
        
        # 确保页码在有效范围内
        page = max(1, min(page, total_pages)) if total_pages > 0 else 1
        
        # 获取分页数据
        logs = query.offset((page - 1) * per_page).limit(per_page).all()

        tasks = db.query(Task).all() # 获取所有任务以用于过滤下拉框

        return templates.TemplateResponse(
            "logs.html",
            {
                "request": request,
                "username": user,
                "logs": logs,
                "tasks": tasks,
                "selected_task_id": task_id,
                "current_page": page,
                "per_page": per_page,
                "total_pages": total_pages,
                "total_count": total_count,
                "min": min  # 添加 min 函数到上下文
            }
        )
    finally:
        db.close()

@app.get("/logs/{log_id}")
async def get_log_details(log_id: int, request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的凭据",
            headers={"WWW-Authenticate": "Basic"},
        )

    try:
        log = db.query(TaskLog).filter(TaskLog.id == log_id).first()
        if not log:
            raise HTTPException(status_code=404, detail="日志未找到")

        elapsed = None
        if log.started_at:
            end_time = log.finished_at or datetime.now()
            elapsed = max(0, int((end_time - log.started_at).total_seconds()))

        return {
            "id": log.id,
            "task_id": log.task_id,
            "task_name": log.task.name if log.task else None,
            "status": log.status,
            "is_running": log.status == "running",
            "elapsed_seconds": elapsed,
            "output": log.output,
            "error": log.error,
            "started_at": log.started_at.isoformat() if log.started_at else None,
            "finished_at": log.finished_at.isoformat() if log.finished_at else None,
        }
    finally:
        db.close()

@app.delete("/logs/{log_id}")
async def delete_log(log_id: int, request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=401, detail="未登录")
        
    # 在数据库中查找并删除日志
    log = db.query(TaskLog).filter(TaskLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="日志不存在")
    if log.status == "running":
        raise HTTPException(status_code=400, detail="任务正在运行，请先停止任务再删除日志")
    
    db.delete(log)
    db.commit()
    
    return {"message": "日志已删除"}

@app.delete("/logs")
async def clear_logs(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的凭据",
            headers={"WWW-Authenticate": "Basic"},
        )

    try:
        # 保留正在运行任务的日志，避免执行中的任务写完日志时记录已被删除
        deleted = db.query(TaskLog).filter(TaskLog.status != "running").delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()

    # DELETE 只把页放入 freelist，必须显式回收，否则数据库文件体积不会下降
    before = os.path.getsize(maintenance.DB_FILE) if os.path.exists(maintenance.DB_FILE) else 0
    vac = await run_in_threadpool(_vacuum_after_delete)
    after = os.path.getsize(maintenance.DB_FILE) if os.path.exists(maintenance.DB_FILE) else 0
    return {
        "message": f"已清除 {deleted} 条日志，回收 {max(0, before - after) / 1024 / 1024:.2f} MB",
        "deleted": deleted,
        "freed": max(0, before - after),
        "vacuum": vac,
    }


def _vacuum_after_delete():
    """清理后立即回收空间；失败不影响清除结果返回。"""
    try:
        return vacuum_db(settings_for_ui()["vacuum_mode"]).get("mode", "none")
    except Exception as exc:
        print(f"[maintenance] 清除日志后回收空间失败: {exc}")
        return "failed"

# 脚本管理相关路由
@app.get("/scripts", response_class=HTMLResponse)
async def list_scripts(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    scripts = db.query(Script).order_by(Script.created_at.desc()).all()
    return templates.TemplateResponse(
        "scripts.html",
        {"request": request, "username": user, "scripts": scripts}
    )

@app.post("/scripts/upload")
async def upload_script(
    request: Request,
    name: Annotated[str, Form(...)],
    file: Annotated[UploadFile, File(...)],
    db=Depends(get_db),
    description: Annotated[Optional[str], Form()] = None,
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    # 验证文件名
    is_valid, result = validate_script_filename(file.filename)
    if not is_valid:
        raise HTTPException(status_code=400, detail=result)

    if db.query(Script).filter(Script.filename == result).first():
        raise HTTPException(status_code=400, detail="同名脚本已存在")

    # 保存文件（落盘名与入库名保持一致，否则后续编辑/执行会找不到文件）
    file_path = safe_join(SCRIPTS_DIR, result)
    await save_upload(file, file_path)

    # 创建数据库记录
    script = Script(
        name=name,
        filename=result,
        description=description
    )
    db.add(script)
    db.commit()

    return JSONResponse({"message": "脚本上传成功"})

@app.get("/scripts/{script_id}/edit", response_class=HTMLResponse)
async def edit_script(script_id: int, request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    script = db.query(Script).filter(Script.id == script_id).first()
    if not script:
        raise HTTPException(status_code=404, detail="脚本不存在")

    # 读取脚本内容
    file_path = safe_join(SCRIPTS_DIR, script.filename)
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="脚本文件不存在")
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    return templates.TemplateResponse(
        "script_edit.html",
        {
            "request": request,
            "username": user,
            "script": script,
            "content": content
        }
    )

@app.post("/scripts/{script_id}/edit")
async def update_script(
    script_id: int,
    request: Request,
    content: str = Form(...),
    filename: str = Form(...),
    description: str = Form(...),
    db=Depends(get_db)
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    script = db.query(Script).filter(Script.id == script_id).first()
    if not script:
        raise HTTPException(status_code=404, detail="脚本不存在")

    # 如果文件名已更改，需要验证并重命名文件
    if filename != script.filename:
        # 验证新文件名
        is_valid, result = validate_script_filename(filename)
        if not is_valid:
            raise HTTPException(status_code=400, detail=result)
        filename = result

        # 检查新文件名是否已存在
        existing_script = db.query(Script).filter(Script.filename == filename).first()
        if existing_script and existing_script.id != script_id:
            raise HTTPException(status_code=400, detail="文件名已存在")

        old_path = safe_join(SCRIPTS_DIR, script.filename)
        new_path = safe_join(SCRIPTS_DIR, filename)
        if os.path.exists(old_path):
            os.rename(old_path, new_path)
        script.filename = filename

    # 更新文件内容
    file_path = safe_join(SCRIPTS_DIR, script.filename)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)

    # 更新描述
    script.description = description
    db.commit()

    return JSONResponse({"message": "脚本更新成功"})

@app.post("/scripts/new")
async def create_script(
    request: Request,
    name: str = Form(...),
    filename: str = Form(...),
    description: Annotated[Optional[str], Form()] = None,
    content: str = Form(...),
    db=Depends(get_db)
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    # 验证文件名
    is_valid, result = validate_script_filename(filename)
    if not is_valid:
        raise HTTPException(status_code=400, detail=result)
    filename = result

    # 检查文件名是否已存在
    existing_script = db.query(Script).filter(Script.filename == filename).first()
    if existing_script:
        raise HTTPException(status_code=400, detail="文件名已存在")

    # 创建文件
    file_path = safe_join(SCRIPTS_DIR, filename)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)

    # 创建数据库记录
    script = Script(
        name=name,
        filename=filename,
        description=description
    )
    db.add(script)
    db.commit()

    return JSONResponse({"message": "脚本创建成功"})

@app.delete("/scripts/{script_id}")
async def delete_script(script_id: int, request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    script = db.query(Script).filter(Script.id == script_id).first()
    if not script:
        raise HTTPException(status_code=404, detail="脚本不存在")

    # 有任务正在运行时禁止删除，避免执行中的进程与日志被中途清理
    tasks = db.query(Task).filter(Task.script_id == script_id).all()
    running = [task.id for task in tasks if is_task_running(task.id)]
    if running:
        raise HTTPException(status_code=400, detail=f"任务 {running} 正在运行，请等待执行结束后再删除脚本")

    # 删除关联的任务
    for task in tasks:
        # 从调度器中移除任务
        remove_job(task.id)
        # 删除任务的日志
        db.query(TaskLog).filter(TaskLog.task_id == task.id).delete()
        # 删除任务
        db.delete(task)

    # 删除关联的文件
    associated_files = db.query(ScriptFile).filter(ScriptFile.script_id == script_id).all()
    for associated_file in associated_files:
        try:
            file_path = safe_join(SCRIPTS_DIR, associated_file.filename)
            if os.path.isfile(file_path):
                os.remove(file_path)
        except Exception as e:
            print(f"删除关联文件时出错: {associated_file.filename}: {e}")
    # 删除关联文件记录从数据库中
    db.query(ScriptFile).filter(ScriptFile.script_id == script_id).delete()

    # 删除脚本文件本身（若与附件同名则已被上面删除，这里仅处理剩余情况）
    try:
        file_path = safe_join(SCRIPTS_DIR, script.filename)
        if os.path.isfile(file_path):
            os.remove(file_path)
    except Exception as e:
        print(f"删除脚本文件时出错: {script.filename}: {e}")

    # 删除数据库记录
    db.delete(script)
    db.commit()

    return JSONResponse({"message": "脚本删除成功"})

@app.get("/scripts/{script_id}/export")
async def export_script(script_id: int, request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    script = db.query(Script).filter(Script.id == script_id).first()
    if not script:
        raise HTTPException(status_code=404, detail="脚本不存在")

    file_path = safe_join(SCRIPTS_DIR, script.filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="脚本文件不存在")

    return FileResponse(path=file_path, filename=script.filename, media_type="text/plain")

# 脚本关联文件相关路由
@app.get("/api/scripts/{script_id}/files")
async def list_script_files(script_id: int, request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    # 验证脚本是否存在
    script = db.query(Script).filter(Script.id == script_id).first()
    if not script:
        raise HTTPException(status_code=404, detail="脚本不存在")

    # 获取脚本的所有关联文件
    files = db.query(ScriptFile).filter(ScriptFile.script_id == script_id).all()
    return files

@app.post("/api/scripts/{script_id}/files")
async def upload_script_file(
    script_id: int,
    files: List[UploadFile] = File(...), # 修改为接收文件列表
    description: Optional[str] = Form(None),
    request: Request = Request,
    db=Depends(get_db)
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    # 验证脚本是否存在并获取脚本信息 (仍然需要用于数据库关联)
    script = db.query(Script).filter(Script.id == script_id).first()
    if not script:
        raise HTTPException(status_code=404, detail="脚本不存在")

    # 确保 /scripts 目录存在
    os.makedirs("scripts", exist_ok=True)

    uploaded_files_info = []
    failed_files = []

    if len(files) > 10:
        raise HTTPException(status_code=400, detail="一次最多上传 10 个文件")

    for file in files:
        try:
            # 只保留纯文件名，拒绝任何路径分隔与穿越片段
            safe_name = sanitize_filename(file.filename)
            file_path = safe_join(SCRIPTS_DIR, safe_name)

            # 检查文件是否已存在
            if os.path.exists(file_path):
                failed_files.append({"original_filename": file.filename, "error": "文件已存在"})
                continue  # 跳过此文件，继续处理下一个

            # 保存文件
            await save_upload(file, file_path)

            # 提取文件类型
            file_extension = os.path.splitext(safe_name)[1]

            # 创建数据库记录
            script_file = ScriptFile(
                script_id=script_id,
                filename=safe_name,
                original_filename=file.filename or safe_name,
                file_type=file_extension[1:] if file_extension else "unknown",
                description=description
            )
            db.add(script_file)
            db.commit()
            db.refresh(script_file)

            uploaded_files_info.append({"original_filename": file.filename, "file_id": script_file.id})
        except HTTPException as e:
            failed_files.append({"original_filename": file.filename, "error": e.detail})
            db.rollback()
        except Exception as e:
            # 如果单个文件上传失败，记录错误并继续处理其他文件
            failed_files.append({"original_filename": file.filename, "error": str(e)})
            # 回滚当前文件的数据库操作（如果已经开始）
            db.rollback()

    if failed_files:
        # 如果有文件上传失败，返回部分成功和失败信息
        # 返回 200 OK 并附带详细信息，以便前端区分处理成功和失败的文件
        return JSONResponse({
            "message": "部分文件上传失败",
            "uploaded": uploaded_files_info,
            "failed": failed_files
        })
    else:
        # 所有文件上传成功
        return JSONResponse({"message": "所有文件上传成功", "uploaded": uploaded_files_info})

@app.get("/api/script-files/{file_id}")
async def get_script_file_details(file_id: int, request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    script_file = db.query(ScriptFile).filter(ScriptFile.id == file_id).first()
    if not script_file:
        raise HTTPException(status_code=404, detail="文件不存在")

    return {
        "id": script_file.id,
        "script_id": script_file.script_id,
        "filename": script_file.filename, # 内部文件名
        "original_filename": script_file.original_filename, # 原始文件名
        "file_type": script_file.file_type,
        "description": script_file.description,
        "created_at": script_file.created_at.strftime('%Y-%m-%d %H:%M:%S') if script_file.created_at else None
    }

@app.get("/api/script-files/{file_id}/content")
async def get_script_file_content(file_id: int, request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    script_file = db.query(ScriptFile).filter(ScriptFile.id == file_id).first()
    if not script_file:
        raise HTTPException(status_code=404, detail="文件不存在")

    file_path = safe_join(SCRIPTS_DIR, script_file.filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="文件不存在")

    try:
        # 尝试以文本模式读取文件内容
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        return content
    except Exception as e:
        # 如果读取失败（例如，非文本文件），返回错误
        raise HTTPException(status_code=400, detail=f"无法读取文件内容，可能不是文本文件或编码错误: {str(e)}")

# 定义用于更新文件的请求体模型
from pydantic import BaseModel

class UpdateScriptFileRequest(BaseModel):
    description: Optional[str] = None
    content: Optional[str] = None # 只在编辑文本文件时提供

@app.put("/api/script-files/{file_id}")
async def update_script_file(
    file_id: int,
    request_body: UpdateScriptFileRequest,
    request: Request,
    db=Depends(get_db)
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    script_file = db.query(ScriptFile).filter(ScriptFile.id == file_id).first()
    if not script_file:
        raise HTTPException(status_code=404, detail="文件不存在")

    # 更新描述
    if request_body.description is not None:
        script_file.description = request_body.description

    # 如果提供了内容，则更新文件内容
    if request_body.content is not None:
        file_path = safe_join(SCRIPTS_DIR, script_file.filename)
        if not os.path.exists(file_path):
             raise HTTPException(status_code=404, detail="文件不存在")

        try:
            # 尝试以文本模式写入文件内容
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(request_body.content)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"保存文件内容失败: {str(e)}")

    db.commit()

    return JSONResponse({"message": "文件更新成功"})

@app.get("/api/script-files/{file_id}/download")
async def download_script_file(file_id: int, request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    # 获取文件信息
    script_file = db.query(ScriptFile).filter(ScriptFile.id == file_id).first()
    if not script_file:
        raise HTTPException(status_code=404, detail="文件不存在")

    file_path = safe_join(SCRIPTS_DIR, script_file.filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="文件不存在")

    return FileResponse(
        path=file_path,
        filename=script_file.original_filename,
        media_type="application/octet-stream"
    )

@app.delete("/api/script-files/{file_id}")
async def delete_script_file(file_id: int, request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    # 获取文件信息
    script_file = db.query(ScriptFile).filter(ScriptFile.id == file_id).first()
    if not script_file:
        raise HTTPException(status_code=404, detail="文件不存在")

    try:
        # 删除物理文件
        file_path = safe_join(SCRIPTS_DIR, script_file.filename)
        if os.path.exists(file_path):
            os.remove(file_path)

        # 删除数据库记录
        db.delete(script_file)
        db.commit()

        return JSONResponse({"message": "文件删除成功"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"文件删除失败: {str(e)}")

# 任务调度相关路由
@app.get("/tasks", response_class=HTMLResponse)
async def list_tasks(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    tasks = db.query(Task).order_by(Task.created_at.desc()).all()

    # 计算每个活动任务的下次运行时间
    tasks_data = []
    for task in tasks:
        next_run = '未计划'
        if task.is_active and task.cron_expression:
            try:
                cron = croniter.croniter(task.cron_expression, datetime.now())
                next_run_time = cron.get_next(datetime)
                next_run = next_run_time.strftime('%Y-%m-%d %H:%M:%S')
            except Exception as e:
                print(f"计算任务 {task.id} 的下次运行时间时出错: {e}")
                next_run = '计算失败'

        # 检查脚本是否存在
        script_name = "未知脚本"
        script_exists = False
        if task.script:
            script_name = task.script.name
            script_exists = True
        else:
            # 如果脚本不存在，将任务标记为非活动状态
            task.is_active = False
            db.commit()

        tasks_data.append({
            "id": task.id,
            "name": task.name,
            "description": task.description,
            "script": {
                "name": script_name,
                "exists": script_exists
            },
            "cron_expression": task.cron_expression,
            "is_active": task.is_active,
            "last_run_at": task.last_run_at,
            "next_run_at": next_run
        })

    scripts = db.query(Script).all()
    return templates.TemplateResponse(
        "tasks.html",
        {
            "request": request,
            "username": user,
            "tasks": tasks_data, # 传递修改后的列表
            "running_task_ids": [item["task_id"] for item in list_running_tasks()],
            "scripts": scripts
        }
    )

@app.post("/tasks")
async def create_task(
    request: Request,
    db=Depends(get_db)
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    data = await read_json_body(request)
    name = data.get("name")
    description = data.get("description")
    script_id = data.get("script_id")
    cron_expression = data.get("cron_expression")

    if not all([name, script_id, cron_expression]):
        raise HTTPException(status_code=400, detail="缺少必要参数")

    # 验证脚本是否存在
    script = db.query(Script).filter(Script.id == script_id).first()
    if not script:
        raise HTTPException(status_code=404, detail="脚本不存在")

    # 验证 cron 表达式（与调度器解析规则保持一致，必须是标准 5 段）
    try:
        validate_cron_expression(cron_expression)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"无效的 cron 表达式: {str(e)}")

    # 创建任务
    task = Task(
        name=name,
        description=description,
        script_id=script_id,
        cron_expression=cron_expression,
        is_active=True  # 默认启用
    )
    db.add(task)
    db.commit()
    db.refresh(task)

    # 添加到调度器；失败则回滚，避免产生无法调度的脏任务
    try:
        add_job(task)
    except Exception as exc:
        db.delete(task)
        db.commit()
        raise HTTPException(status_code=400, detail=f"任务调度注册失败: {exc}")

    return JSONResponse({"message": "任务创建成功"})

@app.get("/api/tasks/{task_id}")
async def get_task(task_id: int, request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")

    # 返回任务详情，包括关联的脚本ID
    return {
        "id": task.id,
        "name": task.name,
        "description": task.description,
        "script_id": task.script_id, # 返回脚本ID
        "cron_expression": task.cron_expression,
        "is_active": task.is_active,
        "last_run_at": task.last_run_at,
        "next_run_at": task.next_run_at
    }

@app.post("/tasks/{task_id}/edit")
async def update_task(
    task_id: int,
    request: Request,
    db=Depends(get_db)
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    data = await read_json_body(request)
    name = data.get("name")
    description = data.get("description")
    script_id = data.get("script_id")
    cron_expression = data.get("cron_expression")

    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")

    # 验证脚本是否存在（如果 script_id 有更新）
    if script_id is not None and script_id != task.script_id:
        script = db.query(Script).filter(Script.id == script_id).first()
        if not script:
            raise HTTPException(status_code=404, detail="选择的脚本不存在")
        task.script_id = script_id

    # 验证 cron 表达式（如果 cron_expression 有更新）
    if cron_expression is not None and cron_expression != task.cron_expression:
        try:
            validate_cron_expression(cron_expression)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"无效的 cron 表达式: {str(e)}")
        task.cron_expression = cron_expression

    # 更新名称和描述（如果提供了）
    if name is not None:
        task.name = name
    if description is not None:
        task.description = description

    db.commit()

    # 如果任务处于活动状态，更新调度器中的任务
    if task.is_active:
        add_job(task)

    return JSONResponse({"message": "任务更新成功"})

@app.post("/tasks/{task_id}/toggle")
async def toggle_task(
    task_id: int,
    request: Request,
    db=Depends(get_db)
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    data = await read_json_body(request)
    is_active = data.get("is_active")

    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")

    task.is_active = bool(is_active)
    db.commit()

    # 更新调度器中的任务
    if task.is_active:
        try:
            add_job(task)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"任务调度注册失败: {exc}")
    else:
        remove_job(task_id)

    return JSONResponse({"message": "任务状态已更新"})

@app.post("/tasks/{task_id}/run")
async def run_task(
    task_id: int,
    request: Request,
    db=Depends(get_db)
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")

    # 并发保护与执行逻辑统一由 scheduler.run_script 负责，避免 Web 与定时触发各自持有一份状态
    if is_task_running(task_id):
        return JSONResponse({"message": "任务正在运行", "status": "running"})

    thread = threading.Thread(
        target=execute_task_script,
        args=(task_id,),
        name=f"beeline-task-{task_id}",
        daemon=True,
    )
    thread.start()

    return JSONResponse({"message": "任务已提交运行"})


@app.get("/api/running-tasks")
async def get_running_tasks(request: Request, db=Depends(get_db)):
    """正在运行的任务列表，供任务页/日志页轮询刷新按钮与实时日志入口。"""
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    items = list_running_tasks()
    name_map = {}
    if items:
        ids = [item["task_id"] for item in items]
        for task in db.query(Task).filter(Task.id.in_(ids)).all():
            name_map[task.id] = task.name
    for item in items:
        item["task_name"] = name_map.get(item["task_id"], f"任务 #{item['task_id']}")
    return {"tasks": items}


@app.post("/api/tasks/{task_id}/stop")
async def stop_task(task_id: int, request: Request, db=Depends(get_db)):
    """停止正在运行的任务。

    进程会被强制终止（含子进程树），日志状态置为 stopped，并记录停止时间。
    """
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")

    if not stop_task_process(task_id):
        return JSONResponse(
            {"message": "任务当前未在运行", "status": "idle"},
            status_code=409,
        )

    return JSONResponse({"message": "已发送停止指令，任务正在终止", "status": "stopping"})


@app.delete("/tasks/{task_id}")
async def delete_task(task_id: int, request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")

    # 检查任务是否正在运行
    if is_task_running(task_id):
        raise HTTPException(status_code=400, detail="任务正在运行中，无法删除")

    # 从调度器中移除任务
    remove_job(task_id)

    # 首先删除关联的日志
    db.query(TaskLog).filter(TaskLog.task_id == task_id).delete()

    # 删除任务
    db.delete(task)
    db.commit()

    return JSONResponse({"message": "任务已删除"})

@app.get("/tasks/{task_id}/latest-log")
async def get_task_latest_log(task_id: int, request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    # 验证任务是否存在
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")

    # 获取任务的最新日志
    latest_log = db.query(TaskLog)\
        .filter(TaskLog.task_id == task_id)\
        .order_by(TaskLog.started_at.desc())\
        .first()

    if not latest_log:
        return {
            "output": "暂无运行记录",
            "error": None,
            "status": None,
            "started_at": None,
            "finished_at": None
        }

    return {
        "output": latest_log.output,
        "error": latest_log.error,
        "status": latest_log.status,
        "started_at": latest_log.started_at.strftime('%Y-%m-%d %H:%M:%S') if latest_log.started_at else None,
        "finished_at": latest_log.finished_at.strftime('%Y-%m-%d %H:%M:%S') if latest_log.finished_at else None
    }

@app.get("/tasks/{task_id}/edit", response_class=HTMLResponse)
async def edit_task(task_id: int, request: Request, db=Depends(get_db)):
    """历史上存在的独立编辑页，模板已不存在；前端使用弹窗编辑，这里重定向回任务列表。"""
    user = get_current_user(request, db=db)
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    return RedirectResponse(url="/tasks", status_code=status.HTTP_302_FOUND)

# 关于页面路由
@app.get("/about", response_class=HTMLResponse)
async def about_page(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse(
        "about.html",
        {
            "request": request,
            "username": user,
            "version": CURRENT_VERSION
        }
    )

def _backup_datetime(value):
    return value.isoformat() if isinstance(value, datetime) else value


def _write_json_section(handle, name, rows, first):
    """以流式方式写入一个 JSON 数组字段，避免把整表日志读进内存。"""
    handle.write(("" if first else ",") + json.dumps(name, ensure_ascii=False) + ":[")
    for index, row in enumerate(rows):
        if index:
            handle.write(",")
        handle.write(json.dumps(row, ensure_ascii=False, default=str))
    handle.write("]")


@app.get("/settings/backup/export")
async def export_backup(request: Request, db=Depends(get_db), include_logs: bool = True):
    user = get_current_user(request, db=db)
    if not user:
        return RedirectResponse(url="/", status_code=302)

    work_dir = tempfile.mkdtemp()
    fd, final_path = tempfile.mkstemp(suffix=".tar.gz")
    os.close(fd)
    try:
        scripts_tar = os.path.join(work_dir, "scripts.tar.gz")
        with tarfile.open(scripts_tar, "w:gz") as tar:
            if os.path.isdir(SCRIPTS_DIR):
                tar.add(SCRIPTS_DIR, arcname="scripts")

        db_json_path = os.path.join(work_dir, "db_data.json")
        with open(db_json_path, "w", encoding="utf-8") as handle:
            handle.write("{")
            _write_json_section(
                handle, "scripts",
                ({k: _backup_datetime(getattr(row, k)) for k in
                  ["id", "name", "filename", "description", "created_at", "updated_at"]}
                 for row in db.query(Script).all()),
                True,
            )
            _write_json_section(
                handle, "tasks",
                ({k: _backup_datetime(getattr(row, k)) for k in
                  ["id", "name", "description", "script_id", "cron_expression", "is_active",
                   "created_at", "last_run_at", "next_run_at"]}
                 for row in db.query(Task).all()),
                False,
            )
            _write_json_section(
                handle, "script_files",
                ({k: _backup_datetime(getattr(row, k)) for k in
                  ["id", "script_id", "filename", "original_filename", "file_type", "description", "created_at"]}
                 for row in db.query(ScriptFile).all()),
                False,
            )
            _write_json_section(
                handle, "env_vars",
                ({k: _backup_datetime(getattr(row, k)) for k in ["id", "key", "value", "created_at"]}
                 for row in db.query(EnvironmentVariable).all()),
                False,
            )
            if include_logs:
                log_rows = (
                    {k: _backup_datetime(getattr(row, k)) for k in
                     ["id", "task_id", "status", "output", "error", "started_at", "finished_at"]}
                    for row in db.query(TaskLog).yield_per(500)
                )
                _write_json_section(handle, "logs", log_rows, False)
            else:
                _write_json_section(handle, "logs", iter(()), False)
            handle.write("}")

        with tarfile.open(final_path, "w:gz") as tar:
            tar.add(scripts_tar, arcname="scripts.tar.gz")
            tar.add(db_json_path, arcname="db_data.json")
    except Exception as exc:
        shutil.rmtree(work_dir, ignore_errors=True)
        try:
            os.remove(final_path)
        except OSError:
            pass
        raise HTTPException(status_code=500, detail=f"导出失败: {exc}")

    shutil.rmtree(work_dir, ignore_errors=True)
    return FileResponse(
        final_path,
        media_type="application/gzip",
        filename="beeline_backup.tar.gz",
        background=BackgroundTask(lambda: os.path.exists(final_path) and os.remove(final_path)),
    )


@app.post("/settings/backup/import")
async def import_backup(request: Request, db=Depends(get_db), backup_file: UploadFile = File(...)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录或会话失效"}, status_code=401)

    temp_dir = tempfile.mkdtemp()
    try:
        backup_path = os.path.join(temp_dir, "imported_backup.tar.gz")
        # 限制体积并流式落盘，避免整包读入内存
        await save_upload(backup_file, backup_path)

        # 外层包（scripts.tar.gz + db_data.json）
        with tarfile.open(backup_path, "r:gz") as tar:
            safe_extract_tar(tar, temp_dir)

        # 内层脚本包
        scripts_tar_path = os.path.join(temp_dir, "scripts.tar.gz")
        if os.path.exists(scripts_tar_path):
            with tarfile.open(scripts_tar_path, "r:gz") as tar:
                safe_extract_tar(tar, temp_dir)

        extracted_scripts = os.path.join(temp_dir, "scripts")
        if os.path.isdir(extracted_scripts):
            for filename in os.listdir(SCRIPTS_DIR):
                file_path = os.path.join(SCRIPTS_DIR, filename)
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            for filename in os.listdir(extracted_scripts):
                src = os.path.join(extracted_scripts, filename)
                dst = os.path.join(SCRIPTS_DIR, filename)
                if os.path.isdir(src):
                    shutil.copytree(src, dst)
                else:
                    shutil.copy2(src, dst)

        db_json_path = os.path.join(temp_dir, "db_data.json")
        if not os.path.exists(db_json_path):
            raise HTTPException(status_code=400, detail="备份包缺少 db_data.json")

        def parse_dt(val):
            if val is None:
                return None
            if isinstance(val, str):
                try:
                    return datetime.fromisoformat(val)
                except Exception:
                    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                        try:
                            return datetime.strptime(val, fmt)
                        except Exception:
                            continue
                    return None
            return val

        with open(db_json_path, "r", encoding="utf-8") as f:
            db_json = json.load(f)
        if not isinstance(db_json, dict):
            raise HTTPException(status_code=400, detail="备份数据格式不正确")

        try:
            # 全部删除与插入放在同一事务中，任一环节失败整体回滚，不会出现“删了没导回”的情况
            db.query(TaskLog).delete()
            db.query(Task).delete()
            db.query(ScriptFile).delete()
            db.query(Script).delete()
            db.query(EnvironmentVariable).delete()
            db.flush()

            for s_ in db_json.get("scripts", []):
                for k in ("created_at", "updated_at"):
                    if k in s_:
                        s_[k] = parse_dt(s_[k])
                db.add(Script(**_pick_columns(s_, Script)))
            db.flush()

            for f_ in db_json.get("script_files", []):
                if "created_at" in f_:
                    f_["created_at"] = parse_dt(f_["created_at"])
                db.add(ScriptFile(**_pick_columns(f_, ScriptFile)))

            for t_ in db_json.get("tasks", []):
                for k in ("created_at", "last_run_at", "next_run_at"):
                    if k in t_:
                        t_[k] = parse_dt(t_[k])
                db.add(Task(**_pick_columns(t_, Task)))
            db.flush()

            for l_ in db_json.get("logs", []):
                for k in ("started_at", "finished_at"):
                    if k in l_:
                        l_[k] = parse_dt(l_[k])
                db.add(TaskLog(**_pick_columns(l_, TaskLog)))

            for e_ in db_json.get("env_vars", []):
                if "created_at" in e_:
                    e_["created_at"] = parse_dt(e_["created_at"])
                db.add(EnvironmentVariable(**_pick_columns(e_, EnvironmentVariable)))

            db.commit()
        except Exception as exc:
            db.rollback()
            raise HTTPException(status_code=400, detail=f"导入失败，数据未变更: {exc}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    # 导入后重载内存状态，避免必须重启才生效
    try:
        env_vars.clear()
        for row in db.query(EnvironmentVariable).all():
            env_vars[row.key] = row.value
        reload_jobs()
    except Exception as exc:
        print(f"导入后重载运行时状态失败: {exc}")

    return JSONResponse({"message": "导入成功"})


def _pick_columns(payload, model):
    """只保留模型真实存在的列，防止备份文件注入未知字段导致异常。"""
    columns = {c.name for c in model.__table__.columns}
    return {k: v for k, v in payload.items() if k in columns}


@app.get("/filemanager", response_class=HTMLResponse)
async def filemanager_page(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(
        "filemanager.html",
        {"request": request, "username": user}
    )

# 文件管理API
import mimetypes

def get_file_tree(root):
    tree = []
    for entry in sorted(os.scandir(root), key=lambda e: (not e.is_dir(), e.name.lower())):
        stat = entry.stat()
        item = {
            "name": entry.name,
            "type": "dir" if entry.is_dir() else "file",
            "size": stat.st_size if not entry.is_dir() else None,  # 返回真实字节数
            "mtime": datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M'),
        }
        if entry.is_dir():
            item["children"] = get_file_tree(entry.path)
        else:
            ext = os.path.splitext(entry.name)[-1][1:].lower()
            item["ext"] = ext
            item["is_text"] = ext in ["txt", "py", "md", "json", "yaml", "yml", "csv", "log", "ini", "conf", "xml", "html", "js", "css"]
        tree.append(item)
    return tree

def _resolve_scripts_path(path: str, must_exist: bool = False, want_file: bool = False) -> str:
    """解析 scripts 目录下的相对路径，越界或类型不符时返回 400。"""
    try:
        abs_path = safe_join(SCRIPTS_DIR, path or "")
    except HTTPException:
        raise HTTPException(status_code=400, detail="无效路径")
    if must_exist and not os.path.exists(abs_path):
        raise HTTPException(status_code=400, detail="无效路径")
    if want_file and not os.path.isfile(abs_path):
        raise HTTPException(status_code=400, detail="无效路径")
    return abs_path


@app.get("/api/filemanager/tree")
async def api_file_tree(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录"}, status_code=401)
    return get_file_tree(SCRIPTS_DIR)


@app.get("/api/filemanager/file")
async def api_get_file(request: Request, path: str, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录"}, status_code=401)
    abs_path = _resolve_scripts_path(path, must_exist=True, want_file=True)
    if os.path.getsize(abs_path) > 10 * 1024 * 1024:
        return JSONResponse({"error": "文件超过 10 MB，请下载后查看"}, status_code=400)
    try:
        with open(abs_path, "r", encoding="utf-8") as f:
            content = f.read()
    except UnicodeDecodeError:
        return JSONResponse({"error": "该文件不是文本文件，无法在线预览"}, status_code=400)
    return {"content": content}


@app.post("/api/filemanager/file")
async def api_save_file(request: Request, path: str, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录"}, status_code=401)
    abs_path = _resolve_scripts_path(path, must_exist=True, want_file=True)
    data = await read_json_body(request)
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(data.get("content", ""))
    return {"message": "保存成功"}


@app.get("/api/filemanager/download")
async def api_download_file(request: Request, path: str, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录"}, status_code=401)
    abs_path = _resolve_scripts_path(path, must_exist=True, want_file=True)
    filename = os.path.basename(abs_path)
    mime, _ = mimetypes.guess_type(abs_path)
    return FileResponse(abs_path, filename=filename, media_type=mime or 'application/octet-stream')


@app.post("/api/filemanager/upload")
async def api_upload_file(request: Request, file: UploadFile = File(...), db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录"}, status_code=401)
    form = await request.form()
    target_folder = (form.get("target_folder") or "").strip()
    try:
        save_dir = _resolve_scripts_path(target_folder) if target_folder else SCRIPTS_DIR
        os.makedirs(save_dir, exist_ok=True)
        save_path = safe_join(save_dir, sanitize_filename(file.filename))
        await save_upload(file, save_path)
    except HTTPException as exc:
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)
    return {"message": "上传成功"}


@app.post("/api/filemanager/upload-folder")
async def api_upload_folder(request: Request, files: list[UploadFile] = File(...), db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录"}, status_code=401)
    uploaded, skipped = 0, []
    for file in files:
        raw_name = (file.filename or "").replace("\\", "/")
        segments = [seg for seg in raw_name.split("/") if seg not in ("", ".")]
        if not segments or any(seg == ".." or _UNSAFE_NAME_CHARS.search(seg) for seg in segments):
            skipped.append(file.filename)
            continue
        try:
            abs_path = safe_join(SCRIPTS_DIR, *segments)
            os.makedirs(os.path.dirname(abs_path), exist_ok=True)
            await save_upload(file, abs_path)
            uploaded += 1
        except HTTPException as exc:
            skipped.append(f"{file.filename}({exc.detail})")
        except Exception:
            skipped.append(file.filename)
    return {"message": f"上传成功 {uploaded} 个文件", "uploaded": uploaded, "skipped": skipped}


@app.post("/api/filemanager/create_folder")
async def api_create_folder(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录"}, status_code=401)
    data = await read_json_body(request)
    foldername = (data.get("foldername") or "").strip()
    if not foldername or any(x in foldername for x in '/\\:*?"<>|'):
        return JSONResponse({"error": "文件夹名不合法"}, status_code=400)
    try:
        abs_path = safe_join(SCRIPTS_DIR, foldername)
    except HTTPException:
        return JSONResponse({"error": "无效路径"}, status_code=400)
    os.makedirs(abs_path, exist_ok=True)
    return {"message": "创建成功"}


@app.post("/api/filemanager/delete")
async def api_delete_entry(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录"}, status_code=401)
    data = await read_json_body(request)
    rel_path = (data.get("path") or "").strip()
    is_dir = data.get("is_dir", False)
    if not rel_path:
        return JSONResponse({"error": "无效路径"}, status_code=400)
    try:
        abs_path = _resolve_scripts_path(rel_path, must_exist=True)
    except HTTPException:
        return JSONResponse({"error": "无效路径"}, status_code=400)
    # 禁止删除脚本根目录本身
    if os.path.realpath(abs_path) == os.path.realpath(SCRIPTS_DIR):
        return JSONResponse({"error": "不能删除根目录"}, status_code=400)
    try:
        if is_dir or os.path.isdir(abs_path):
            shutil.rmtree(abs_path)
        else:
            os.remove(abs_path)
        return {"message": "删除成功"}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/filemanager/rename")
async def api_rename_entry(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录"}, status_code=401)
    data = await read_json_body(request)
    rel_path = (data.get("path") or "").strip()
    new_name = (data.get("new_name") or "").strip()
    if not rel_path:
        return JSONResponse({"error": "无效路径"}, status_code=400)
    if not new_name or any(x in new_name for x in '/\\:*?"<>|') or new_name in (".", ".."):
        return JSONResponse({"error": "新名称不合法"}, status_code=400)
    try:
        abs_path = _resolve_scripts_path(rel_path, must_exist=True)
        new_abs_path = safe_join(os.path.dirname(abs_path), new_name)
    except HTTPException:
        return JSONResponse({"error": "无效路径"}, status_code=400)
    try:
        os.rename(abs_path, new_abs_path)
        return {"message": "重命名成功"}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False, reload_dirs=["templates", "static"])
