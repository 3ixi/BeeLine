from fastapi import FastAPI, Request, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import uvicorn
import os
from datetime import datetime, timedelta
from typing import Optional, List
import secrets
from pathlib import Path
import shutil
from models import SessionLocal, Script, Task, TaskLog, User, EnvironmentVariable, Session
import sqlalchemy as sa
import subprocess
import threading
import croniter
import json
import sys
from typing_extensions import Annotated
from scheduler import init_scheduler, add_job, remove_job, shutdown_scheduler, running_tasks, env_vars
from contextlib import asynccontextmanager

from passlib.context import CryptContext

# 创建密码哈希的上下文
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 定义当前版本
CURRENT_VERSION = "1.0.2"

# 创建必要的目录
os.makedirs("static", exist_ok=True)
os.makedirs("templates", exist_ok=True)
os.makedirs("scripts", exist_ok=True)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时执行
    db = SessionLocal()
    try:
        # 检查是否存在任何用户
        user_count = db.query(User).count()
        if user_count == 0:
            # 没有找到用户，创建默认的管理员用户
            default_username = "admin"
            default_password = os.environ.get("DEFAULT_ADMIN_PASSWORD", "admin")
            hashed_password = get_password_hash(default_password)
            default_user = User(username=default_username, hashed_password=hashed_password)
            db.add(default_user)
            db.commit()
            print(f"默认管理员用户 '{default_username}' 已创建。")
        else:
            print(f"在数据库中找到 {user_count} 个用户。没有创建默认用户。")

        # 加载环境变量
        global env_vars
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

    yield

    # 关闭时执行
    shutdown_scheduler()

app = FastAPI(title="BeeLine Web Controller", lifespan=lifespan)

# 挂载静态文件
app.mount("/static", StaticFiles(directory="static"), name="static")

# 设置模板
templates = Jinja2Templates(directory="templates")

# 存储运行中的任务
running_tasks = {}

# 存储环境变量
env_vars = {}

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(request: Request, db: SessionLocal = Depends(get_db)) -> Optional[str]:
    session_id = request.cookies.get("session_id")
    if session_id:
        # 在数据库中查找会话
        session = db.query(Session).filter(Session.id == session_id).first()
        if session and datetime.now() < session.expires:
            # 更新会话的活动过期时间（可选）
            session.expires = datetime.now() + timedelta(days=7)
            db.commit()
            return session.username
        elif session:
            # 会话已过期，从数据库中删除
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
async def root(request: Request, db: SessionLocal = Depends(get_db)):
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
async def login(request: Request, db: SessionLocal = Depends(get_db)):
    form_data = await request.form()
    username = form_data.get("username")
    password = form_data.get("password")

    # 在数据库中查找用户
    user = db.query(User).filter(User.username == username).first()

    # 验证密码
    if user and verify_password(password, user.hashed_password):
        session_id = secrets.token_urlsafe(32)
        # 在数据库中存储会话
        new_session = Session(
            id=session_id,
            username=user.username,
            expires=datetime.now() + timedelta(days=7)
        )
        db.add(new_session)
        db.commit()

        response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
        response.set_cookie(
            key="session_id",
            value=session_id,
            expires=timedelta(days=7), # 设置 cookie 过期时间
            httponly=True,
            # secure=True, # 在生产环境中使用 HTTPS 时取消注释
            # samesite="Strict" # 如需更严格的安全措施，请取消注释
        )
        return response

    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "无效的凭据"}
    )

@app.get("/logout")
async def logout(request: Request, db: SessionLocal = Depends(get_db)):
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
async def settings_page(request: Request, db: SessionLocal = Depends(get_db)):
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
            "current_username": current_user_db.username # 将当前用户名传递给模板
        }
    )

@app.post("/settings")
async def update_settings(request: Request, db: SessionLocal = Depends(get_db)):
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

    # 验证当前密码
    if not verify_password(current_password, current_user_db.hashed_password):
        return templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "username": user,
                "current_username": current_user_db.username,
                "error": "当前密码不正确"
            }
        )

    # 如果提供了新用户名且不同，则更新用户名
    if new_username and new_username != current_user_db.username:
        # 检查新用户名是否已存在
        existing_user = db.query(User).filter(User.username == new_username).first()
        if existing_user:
             return templates.TemplateResponse(
                "settings.html",
                {
                    "request": request,
                    "username": user,
                    "current_username": current_user_db.username,
                    "error": "新用户名已存在"
                }
            )
        current_user_db.username = new_username
        # 如果更改了，则在数据库中更新会话用户名
        db.query(Session).filter(Session.username == user).update({"username": new_username})
        db.commit()
        user = new_username # 更新用户变量以渲染模板


    # 如果提供了新密码，则更新密码
    if new_password:
        if new_password != confirm_password:
             return templates.TemplateResponse(
                "settings.html",
                {
                    "request": request,
                    "username": user,
                    "current_username": current_user_db.username,
                    "error": "新密码和确认密码不匹配"
                }
            )
        current_user_db.hashed_password = get_password_hash(new_password)

    db.commit()

    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "username": user,
            "current_username": current_user_db.username,
            "message": "设置已更新成功"
        }
    )

# 环境变量管理
@app.get("/env", response_class=HTMLResponse)
async def list_env_vars(request: Request, db: SessionLocal = Depends(get_db)):
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
async def set_env_var(request: Request, db: SessionLocal = Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    data = await request.json()
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
async def get_env_var(key: str, request: Request, db: SessionLocal = Depends(get_db)):
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
async def delete_env_var(key: str, request: Request, db: SessionLocal = Depends(get_db)):
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
async def list_packages(request: Request, db: SessionLocal = Depends(get_db)):
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
async def search_packages(request: Request, search: str = "", db: SessionLocal = Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    try:
        # 使用 subprocess 运行 pip list 命令并获取 JSON 输出
        result = subprocess.run(
            ["pip", "list", "--format=json"],
            capture_output=True,
            text=True,
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
async def install_package(request: Request, db: SessionLocal = Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    try:
        data = await request.json()
        package_name = data.get("name")
        package_version = data.get("version")

        if not package_name:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="包名不能为空")

        command = ["pip", "install", package_name]
        if package_version:
            command.append(f"{package_name}=={package_version}")

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )

        return JSONResponse({"message": f"包 {package_name} 安装成功", "output": process.stdout})

    except subprocess.CalledProcessError as e:
        print(f"安装包时出错: {e.stderr}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"安装失败: {e.stderr}")
    except Exception as e:
        print(f"安装包时发生未知错误: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"安装失败: {e}")

# 日志管理
@app.get("/logs", response_class=HTMLResponse)
async def list_logs(request: Request, db: SessionLocal = Depends(get_db), task_id: Optional[int] = None):
    user = get_current_user(request, db=db)
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    try:
        query = db.query(TaskLog).order_by(TaskLog.started_at.desc())
        if task_id is not None:
            query = query.filter(TaskLog.task_id == task_id)
        logs = query.all()

        tasks = db.query(Task).all() # 获取所有任务以用于过滤下拉框

        return templates.TemplateResponse(
            "logs.html",
            {
                "request": request,
                "username": user,
                "logs": logs,
                "tasks": tasks, # 传递任务到模板
                "selected_task_id": task_id # 传递选中的任务ID以用于下拉框选择
            }
        )
    finally:
        db.close()

@app.get("/logs/{log_id}")
async def get_log_details(log_id: int, request: Request, db: SessionLocal = Depends(get_db)):
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

        return {
            "output": log.output,
            "error": log.error
        }
    finally:
        db.close()

@app.delete("/logs")
async def clear_logs(request: Request, db: SessionLocal = Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的凭据",
            headers={"WWW-Authenticate": "Basic"},
        )

    try:
        db.query(TaskLog).delete()
        db.commit()
        return {"message": "日志已清除成功"}
    finally:
        db.close()

# 脚本管理相关路由
@app.get("/scripts", response_class=HTMLResponse)
async def list_scripts(request: Request, db: SessionLocal = Depends(get_db)):
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
    description: Annotated[str, Form(...)],
    file: Annotated[UploadFile, File(...)],
    db: Annotated[SessionLocal, Depends(get_db)]
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    if not file.filename.endswith('.py'):
        raise HTTPException(status_code=400, detail="只支持上传Python脚本文件")

    # 保存文件
    file_path = os.path.join("scripts", file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # 创建数据库记录
    script = Script(
        name=name,
        filename=file.filename,
        description=description
    )
    db.add(script)
    db.commit()

    return JSONResponse({"message": "脚本上传成功"})

@app.get("/scripts/{script_id}/edit", response_class=HTMLResponse)
async def edit_script(script_id: int, request: Request, db: SessionLocal = Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    script = db.query(Script).filter(Script.id == script_id).first()
    if not script:
        raise HTTPException(status_code=404, detail="脚本不存在")

    # 读取脚本内容
    file_path = os.path.join("scripts", script.filename)
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
    db: SessionLocal = Depends(get_db)
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    script = db.query(Script).filter(Script.id == script_id).first()
    if not script:
        raise HTTPException(status_code=404, detail="脚本不存在")

    # 如果文件名已更改，需要重命名文件
    if filename != script.filename:
        old_path = os.path.join("scripts", script.filename)
        new_path = os.path.join("scripts", filename)
        if os.path.exists(old_path):
            os.rename(old_path, new_path)
        script.filename = filename

    # 更新文件内容
    file_path = os.path.join("scripts", script.filename)
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
    description: str = Form(...),
    content: str = Form(...),
    db: SessionLocal = Depends(get_db)
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    # 检查文件名是否已存在
    existing_script = db.query(Script).filter(Script.filename == filename).first()
    if existing_script:
        raise HTTPException(status_code=400, detail="文件名已存在")

    # 确保文件名以.py结尾
    if not filename.endswith('.py'):
        filename += '.py'

    # 创建文件
    file_path = os.path.join("scripts", filename)
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
async def delete_script(script_id: int, request: Request, db: SessionLocal = Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    script = db.query(Script).filter(Script.id == script_id).first()
    if not script:
        raise HTTPException(status_code=404, detail="脚本不存在")

    # 删除文件
    file_path = os.path.join("scripts", script.filename)
    if os.path.exists(file_path):
        os.remove(file_path)

    # 删除数据库记录
    db.delete(script)
    db.commit()

    return JSONResponse({"message": "脚本删除成功"})

@app.get("/scripts/{script_id}/export")
async def export_script(script_id: int, request: Request, db: SessionLocal = Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    script = db.query(Script).filter(Script.id == script_id).first()
    if not script:
        raise HTTPException(status_code=404, detail="脚本不存在")

    file_path = os.path.join("scripts", script.filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="脚本文件不存在")

    return FileResponse(path=file_path, filename=script.filename, media_type="text/plain")

# 任务调度相关路由
@app.get("/tasks", response_class=HTMLResponse)
async def list_tasks(request: Request, db: SessionLocal = Depends(get_db)):
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

        tasks_data.append({
            "id": task.id,
            "name": task.name,
            "description": task.description,
            "script": {"name": task.script.name}, # 包含脚本名称
            "cron_expression": task.cron_expression,
            "is_active": task.is_active,
            "last_run_at": task.last_run_at,
            "next_run_at": next_run # 添加计算的下次运行时间
        })

    scripts = db.query(Script).all()
    return templates.TemplateResponse(
        "tasks.html",
        {
            "request": request,
            "username": user,
            "tasks": tasks_data, # 传递修改后的列表
            "scripts": scripts
        }
    )

@app.post("/tasks")
async def create_task(
    request: Request,
    db: SessionLocal = Depends(get_db)
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    data = await request.json()
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

    # 验证 cron 表达式
    try:
        croniter.croniter(cron_expression, datetime.now())
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

    # 添加到调度器
    add_job(task)

    return JSONResponse({"message": "任务创建成功"})

@app.get("/api/tasks/{task_id}")
async def get_task(task_id: int, request: Request, db: SessionLocal = Depends(get_db)):
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
    db: SessionLocal = Depends(get_db)
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    data = await request.json()
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
            croniter.croniter(cron_expression, datetime.now())
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
    db: SessionLocal = Depends(get_db)
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    data = await request.json()
    is_active = data.get("is_active")

    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")

    task.is_active = is_active
    db.commit()

    # 更新调度器中的任务
    if is_active:
        add_job(task)
    else:
        remove_job(task_id)

    return JSONResponse({"message": "任务状态已更新"})

@app.post("/tasks/{task_id}/run")
async def run_task(
    task_id: int,
    request: Request,
    db: SessionLocal = Depends(get_db)
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")

    # 检查任务是否正在运行
    if task_id in running_tasks:
        raise HTTPException(status_code=400, detail="任务正在运行中")

    # 为避免线程安全问题，为线程创建一个新的数据库会话
    def run_script():
        db_thread = SessionLocal()
        try:
            # 在线程的数据库会话中创建任务日志
            task_log = TaskLog(
                task_id=task_id,
                status="running"
            )
            db_thread.add(task_log)
            db_thread.commit()
            db_thread.refresh(task_log) # 刷新以获取日志ID（如果需要）

            # 在线程的数据库会话中重新查询任务
            task_thread = db_thread.query(Task).filter(Task.id == task_id).first()
            if not task_thread:
                 print(f"任务 {task_id} 未找到。")
                 return # 如果任务未找到，则退出

            # 在线程的数据库会话中重新查询脚本
            script_thread = db_thread.query(Script).filter(Script.id == task_thread.script_id).first()
            if not script_thread:
                 print(f"任务 {task_id} 的脚本未找到。")
                 return # 如果脚本未找到，则退出

            script_path = os.path.join("scripts", script_thread.filename)
            
            # 准备用于子进程的环境变量
            subprocess_env = os.environ.copy()
            subprocess_env.update(env_vars)

            process = subprocess.Popen(
                ["python", script_thread.filename],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=subprocess_env, # 传递正确更新的环境变量
                cwd="scripts" # 在子进程中设置工作目录
            )
            stdout, stderr = process.communicate()

            # 使用线程的数据库会话更新任务日志
            log_to_update = db_thread.query(TaskLog).filter(TaskLog.id == task_log.id).first()
            if log_to_update:
                log_to_update.status = "success" if process.returncode == 0 else "failed"
                log_to_update.output = stdout
                log_to_update.error = stderr
                log_to_update.finished_at = datetime.now()
                db_thread.commit()

            # 使用线程的数据库会话更新任务状态
            task_to_update = db_thread.query(Task).filter(Task.id == task_id).first()
            if task_to_update:
                 task_to_update.last_run_at = datetime.now()
                 if task_to_update.is_active:
                     cron = croniter.croniter(task_to_update.cron_expression, datetime.now())
                     task_to_update.next_run_at = cron.get_next(datetime)
                 db_thread.commit()

        except Exception as e:
            # 如果脚本执行失败，则记录错误
            log_to_update = db_thread.query(TaskLog).filter(TaskLog.task_id == task_id, TaskLog.status == "running").order_by(TaskLog.started_at.desc()).first() # 尝试找到正在运行的日志
            if log_to_update:
                log_to_update.status = "failed"
                log_to_update.error = str(e)
                log_to_update.finished_at = datetime.now()
                db_thread.commit()
            print(f"Error running task {task_id}: {e}")
        finally:
            db_thread.close()
            running_tasks.pop(task_id, None)

    # 启动后台线程
    thread = threading.Thread(target=run_script)
    thread.start()
    running_tasks[task_id] = thread

    return JSONResponse({"message": "任务已开始运行"})

@app.delete("/tasks/{task_id}")
async def delete_task(task_id: int, request: Request, db: SessionLocal = Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")

    # 检查任务是否正在运行
    if task_id in running_tasks:
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
async def get_task_latest_log(task_id: int, request: Request, db: SessionLocal = Depends(get_db)):
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
async def edit_task(task_id: int, request: Request, db: SessionLocal = Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")

    scripts = db.query(Script).all() # 需要脚本列表供选择

    return templates.TemplateResponse(
        "task_edit.html",
        {
            "request": request,
            "username": user,
            "task": task,
            "scripts": scripts
        }
    )

# 关于页面路由
@app.get("/about", response_class=HTMLResponse)
async def about_page(request: Request, db: SessionLocal = Depends(get_db)):
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

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False, reload_dirs=["templates", "static"]) 