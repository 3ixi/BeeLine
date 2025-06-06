from fastapi import FastAPI, Request, Depends, HTTPException, status, UploadFile, File, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import uvicorn
import os
import io
import tarfile
import tempfile
import shutil
import json
import sys
from datetime import datetime, timedelta
from typing import Optional, List
import secrets
from pathlib import Path
import subprocess
import threading
import croniter
from typing_extensions import Annotated
from scheduler import init_scheduler, add_job, remove_job, shutdown_scheduler, running_tasks, env_vars
from contextlib import asynccontextmanager

from passlib.context import CryptContext
from models import SessionLocal, Script, Task, TaskLog, User, EnvironmentVariable, Session, ScriptFile

# 创建密码哈希的上下文
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 定义当前版本
CURRENT_VERSION = "1.0.8"

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

def validate_script_filename(filename):
    """验证脚本文件名是否合法
    
    Args:
        filename: 要验证的文件名
        
    Returns:
        tuple: (是否合法, 错误信息/处理后的文件名)
    """
    if ' ' in filename:
        return False, "文件名不能包含空格"
    if not filename.endswith('.py'):
        filename += '.py'
    return True, filename

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
            "current_username": current_user_db.username # 将当前用户名传递给模板
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
async def install_package(request: Request, db=Depends(get_db)):
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
async def list_logs(request: Request, db=Depends(get_db), task_id: Optional[int] = None, page: int = 1, per_page: int = 15, only_errors: Optional[str] = None):
    user = get_current_user(request, db=db)
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

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

        return {
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
        db.query(TaskLog).delete()
        db.commit()
        return {"message": "日志已清除成功"}
    finally:
        db.close()

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
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")    # 验证文件名
    is_valid, result = validate_script_filename(file.filename)
    if not is_valid:
        raise HTTPException(status_code=400, detail=result)

    # 保存文件
    file_path = os.path.join("scripts", result)
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
async def edit_script(script_id: int, request: Request, db=Depends(get_db)):
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
    db=Depends(get_db)
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    script = db.query(Script).filter(Script.id == script_id).first()
    if not script:
        raise HTTPException(status_code=404, detail="脚本不存在")    # 如果文件名已更改，需要验证并重命名文件
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
    description: Annotated[Optional[str], Form()] = None,
    content: str = Form(...),
    db=Depends(get_db)
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")    # 验证文件名
    is_valid, result = validate_script_filename(filename)
    if not is_valid:
        raise HTTPException(status_code=400, detail=result)
    filename = result

    # 检查文件名是否已存在
    existing_script = db.query(Script).filter(Script.filename == filename).first()
    if existing_script:
        raise HTTPException(status_code=400, detail="文件名已存在")

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
async def delete_script(script_id: int, request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    script = db.query(Script).filter(Script.id == script_id).first()
    if not script:
        raise HTTPException(status_code=404, detail="脚本不存在")

    # 删除关联的任务
    tasks = db.query(Task).filter(Task.script_id == script_id).all()
    for task in tasks:
        # 从调度器中移除任务
        remove_job(task.id)
        # 删除任务的日志
        db.query(TaskLog).filter(TaskLog.task_id == task.id).delete()
        # 删除任务
        db.delete(task)

    # 删除关联的文件
    associated_files = db.query(ScriptFile).filter(ScriptFile.script_id == script_id).all()
    print(f"尝试删除脚本 ID 为 {script_id} 的{len(associated_files)} 个关联文件")
    for associated_file in associated_files:
        file_path = os.path.join("scripts", associated_file.filename)
        print(f"检查文件路径: {file_path}")
        if os.path.exists(file_path):
            print(f"文件存在: {file_path}. 尝试删除。")
            try:
                os.remove(file_path)
                print(f"已删除关联文件: {file_path}")
            except Exception as e:
                print(f"删除关联文件时出错: {file_path}: {e}")
        else:
            print(f"文件不存在: {file_path}")
    print(f"已尝试删除脚本 ID 为 {script_id} 的关联文件")
    # 删除关联文件记录从数据库中
    db.query(ScriptFile).filter(ScriptFile.script_id == script_id).delete()

    # 删除文件
    file_path = os.path.join("scripts", script.filename)
    if os.path.exists(file_path):
        os.remove(file_path)

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

    file_path = os.path.join("scripts", script.filename)
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
            # 使用原始文件名构建文件路径
            file_path = os.path.join("scripts", file.filename)

            # 检查文件是否已存在
            if os.path.exists(file_path):
                failed_files.append({"original_filename": file.filename, "error": "文件已存在"})
                continue  # 跳过此文件，继续处理下一个

            # 保存文件
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            # 提取文件类型
            file_extension = os.path.splitext(file.filename)[1]

            # 创建数据库记录
            script_file = ScriptFile(
                script_id=script_id,
                # 在数据库中保存原始文件名
                filename=file.filename, # 这里存储原始文件名
                original_filename=file.filename, # 这里存储原始文件名
                file_type=file_extension[1:] if file_extension else "unknown",
                description=description # 同一个描述应用于所有文件，或者前端可以提供单独的描述字段
            )
            db.add(script_file)
            db.commit()
            db.refresh(script_file)

            uploaded_files_info.append({"original_filename": file.filename, "file_id": script_file.id})
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

    file_path = os.path.join(
        "scripts", script_file.filename # 直接在 scripts 目录下
    )
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
        file_path = os.path.join("scripts", script_file.filename) # 直接在 scripts 目录下
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

    file_path = os.path.join(
        "scripts", script_file.filename # 直接在 scripts 目录下
    )
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
        file_path = os.path.join("scripts", script_file.filename) # 直接在 scripts 目录下
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
    db=Depends(get_db)
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
    db=Depends(get_db)
):
    user = get_current_user(request, db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未授权")

    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")    # 检查任务是否正在运行
    if task_id in running_tasks:
        return JSONResponse({"message": "任务正在运行", "status": "running"})

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
            subprocess_env['PYTHONIOENCODING'] = 'utf-8'  # 设置Python IO编码

            process = subprocess.Popen(
                ["python", script_thread.filename],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',  # 设置输出编码
                errors='replace',  # 处理无法解码的字符
                env=subprocess_env,
                cwd="scripts"  # 设置工作目录
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
            print(f"任务运行错误 {task_id}: {e}")
        finally:
            db_thread.close()
            running_tasks.pop(task_id, None)

    # 启动后台线程
    thread = threading.Thread(target=run_script)
    thread.start()
    running_tasks[task_id] = thread

    return JSONResponse({"message": "任务已提交运行"})

@app.delete("/tasks/{task_id}")
async def delete_task(task_id: int, request: Request, db=Depends(get_db)):
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

@app.get("/settings/backup/export")
async def export_backup(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return RedirectResponse(url="/", status_code=302)
    scripts_dir = os.path.abspath("scripts")
    temp_dir = tempfile.mkdtemp()
    scripts_tar = os.path.join(temp_dir, "scripts.tar.gz")
    with tarfile.open(scripts_tar, "w:gz") as tar:
        tar.add(scripts_dir, arcname="scripts")
    scripts = db.query(Script).all()
    scripts_data = [
        {k: getattr(s, k) for k in ["id", "name", "filename", "description", "created_at", "updated_at"]}
        for s in scripts
    ]
    tasks = db.query(Task).all()
    tasks_data = [
        {k: getattr(t, k) for k in ["id", "name", "description", "script_id", "cron_expression", "is_active", "created_at", "last_run_at", "next_run_at"]}
        for t in tasks
    ]
    logs = db.query(TaskLog).all()
    logs_data = [
        {k: getattr(l, k) for k in ["id", "task_id", "status", "output", "error", "started_at", "finished_at"]}
        for l in logs
    ]
    script_files = db.query(ScriptFile).all()
    script_files_data = [
        {k: getattr(f, k) for k in ["id", "script_id", "filename", "original_filename", "file_type", "description", "created_at"]}
        for f in script_files
    ]
    env_vars = db.query(EnvironmentVariable).all()
    env_vars_data = [
        {k: getattr(e, k) for k in ["id", "key", "value", "created_at"]}
        for e in env_vars
    ]
    db_json = {
        "scripts": scripts_data,
        "tasks": tasks_data,
        "logs": logs_data,
        "script_files": script_files_data,
        "env_vars": env_vars_data
    }
    db_json_path = os.path.join(temp_dir, "db_data.json")
    with open(db_json_path, "w", encoding="utf-8") as f:
        json.dump(db_json, f, ensure_ascii=False, default=str, indent=2)
    final_tar_path = os.path.join(temp_dir, "beeline_backup.tar.gz")
    with tarfile.open(final_tar_path, "w:gz") as tar:
        tar.add(scripts_tar, arcname="scripts.tar.gz")
        tar.add(db_json_path, arcname="db_data.json")
    with open(final_tar_path, "rb") as f:
        data = f.read()
    shutil.rmtree(temp_dir)
    return Response(data, media_type="application/gzip", headers={
        "Content-Disposition": "attachment; filename=beeline_backup.tar.gz"
    })

@app.post("/settings/backup/import")
async def import_backup(request: Request, db=Depends(get_db), backup_file: UploadFile = File(...)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录或会话失效"}, status_code=401)
    temp_dir = tempfile.mkdtemp()
    backup_path = os.path.join(temp_dir, "imported_backup.tar.gz")
    with open(backup_path, "wb") as f:
        f.write(await backup_file.read())
    with tarfile.open(backup_path, "r:gz") as tar:
        tar.extractall(temp_dir)
    scripts_tar_path = os.path.join(temp_dir, "scripts.tar.gz")
    scripts_extract_dir = os.path.join(temp_dir, "scripts")
    if os.path.exists(scripts_tar_path):
        with tarfile.open(scripts_tar_path, "r:gz") as tar:
            tar.extractall(temp_dir)
    scripts_dir = os.path.abspath("scripts")
    if os.path.exists(os.path.join(temp_dir, "scripts")):
        for filename in os.listdir(scripts_dir):
            file_path = os.path.join(scripts_dir, filename)
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        for filename in os.listdir(os.path.join(temp_dir, "scripts")):
            src = os.path.join(temp_dir, "scripts", filename)
            dst = os.path.join(scripts_dir, filename)
            if os.path.isdir(src):
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
    db_json_path = os.path.join(temp_dir, "db_data.json")
    def parse_dt(val):
        if val is None:
            return None
        if isinstance(val, str):
            try:
                return datetime.fromisoformat(val)
            except Exception:
                try:
                    return datetime.strptime(val, "%Y-%m-%d %H:%M:%S.%f")
                except Exception:
                    try:
                        return datetime.strptime(val, "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        return None
        return val
    if os.path.exists(db_json_path):
        with open(db_json_path, "r", encoding="utf-8") as f:
            db_json = json.load(f)
        db.query(TaskLog).delete()
        db.query(Task).delete()
        db.query(ScriptFile).delete()
        db.query(Script).delete()
        db.query(EnvironmentVariable).delete()
        db.commit()
        # 脚本
        for s in db_json.get("scripts", []):
            for k in ("created_at", "updated_at"):
                if k in s:
                    s[k] = parse_dt(s[k])
            db.add(Script(**s))
        db.commit()
        # 脚本文件
        for f_ in db_json.get("script_files", []):
            for k in ("created_at", ):
                if k in f_:
                    f_[k] = parse_dt(f_[k])
            db.add(ScriptFile(**f_))
        db.commit()
        # 任务
        for t in db_json.get("tasks", []):
            for k in ("created_at", "last_run_at", "next_run_at"):
                if k in t:
                    t[k] = parse_dt(t[k])
            db.add(Task(**t))
        db.commit()
        # 日志
        for l in db_json.get("logs", []):
            for k in ("started_at", "finished_at"):
                if k in l:
                    l[k] = parse_dt(l[k])
            db.add(TaskLog(**l))
        db.commit()
        # 环境变量
        for e in db_json.get("env_vars", []):
            for k in ("created_at", ):
                if k in e:
                    e[k] = parse_dt(e[k])
            db.add(EnvironmentVariable(**e))
        db.commit()
    shutil.rmtree(temp_dir)
    return JSONResponse({"message": "导入成功"})

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

@app.get("/api/filemanager/tree")
async def api_file_tree(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录"}, status_code=401)
    root = os.path.abspath("scripts")
    return get_file_tree(root)

@app.get("/api/filemanager/file")
async def api_get_file(request: Request, path: str, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录"}, status_code=401)
    abs_path = os.path.abspath(os.path.join("scripts", path))
    if not abs_path.startswith(os.path.abspath("scripts")) or not os.path.isfile(abs_path):
        return JSONResponse({"error": "无效路径"}, status_code=400)
    with open(abs_path, "r", encoding="utf-8") as f:
        content = f.read()
    return {"content": content}

@app.post("/api/filemanager/file")
async def api_save_file(request: Request, path: str, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录"}, status_code=401)
    abs_path = os.path.abspath(os.path.join("scripts", path))
    if not abs_path.startswith(os.path.abspath("scripts")) or not os.path.isfile(abs_path):
        return JSONResponse({"error": "无效路径"}, status_code=400)
    data = await request.json()
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(data.get("content", ""))
    return {"message": "保存成功"}

@app.get("/api/filemanager/download")
async def api_download_file(request: Request, path: str, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录"}, status_code=401)
    abs_path = os.path.abspath(os.path.join("scripts", path))
    if not abs_path.startswith(os.path.abspath("scripts")) or not os.path.isfile(abs_path):
        return JSONResponse({"error": "无效路径"}, status_code=400)
    filename = os.path.basename(abs_path)
    mime, _ = mimetypes.guess_type(abs_path)
    return FileResponse(abs_path, filename=filename, media_type=mime or 'application/octet-stream')

@app.post("/api/filemanager/upload")
async def api_upload_file(request: Request, file: UploadFile = File(...), db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录"}, status_code=401)
    form = await request.form()
    target_folder = form.get("target_folder", "").strip()
    # 兼容根目录和子目录
    save_dir = os.path.join("scripts", target_folder) if target_folder else "scripts"
    os.makedirs(save_dir, exist_ok=True)
    save_path = os.path.join(save_dir, file.filename)
    abs_path = os.path.abspath(save_path)
    if not abs_path.startswith(os.path.abspath("scripts")):
        return JSONResponse({"error": "无效路径"}, status_code=400)
    with open(abs_path, "wb") as f:
        f.write(await file.read())
    return {"message": "上传成功"}

@app.post("/api/filemanager/upload-folder")
async def api_upload_folder(request: Request, files: list[UploadFile] = File(...), db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录"}, status_code=401)
    for file in files:
        rel_path = file.filename.replace("..", "_") # 防止目录穿越
        save_path = os.path.join("scripts", rel_path)
        abs_path = os.path.abspath(save_path)
        if not abs_path.startswith(os.path.abspath("scripts")):
            continue
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "wb") as f:
            f.write(await file.read())
    return {"message": "上传成功"}

@app.post("/api/filemanager/create_folder")
async def api_create_folder(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录"}, status_code=401)
    data = await request.json()
    foldername = data.get("foldername", "").strip()
    if not foldername or any(x in foldername for x in '/\\'):
        return JSONResponse({"error": "文件夹名不合法"}, status_code=400)
    abs_path = os.path.abspath(os.path.join("scripts", foldername))
    if not abs_path.startswith(os.path.abspath("scripts")):
        return JSONResponse({"error": "无效路径"}, status_code=400)
    os.makedirs(abs_path, exist_ok=True)
    return {"message": "创建成功"}

@app.post("/api/filemanager/delete")
async def api_delete_entry(request: Request, db=Depends(get_db)):
    user = get_current_user(request, db=db)
    if not user:
        return JSONResponse({"error": "未登录"}, status_code=401)
    data = await request.json()
    rel_path = data.get("path", "").strip()
    is_dir = data.get("is_dir", False)
    abs_path = os.path.abspath(os.path.join("scripts", rel_path))
    if not abs_path.startswith(os.path.abspath("scripts")) or not os.path.exists(abs_path):
        return JSONResponse({"error": "无效路径"}, status_code=400)
    try:
        if is_dir:
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
    data = await request.json()
    rel_path = data.get("path", "").strip()
    new_name = data.get("new_name", "").strip()
    is_dir = data.get("is_dir", False)
    if not new_name or any(x in new_name for x in '/\\'):
        return JSONResponse({"error": "新名称不合法"}, status_code=400)
    abs_path = os.path.abspath(os.path.join("scripts", rel_path))
    if not abs_path.startswith(os.path.abspath("scripts")) or not os.path.exists(abs_path):
        return JSONResponse({"error": "无效路径"}, status_code=400)
    new_abs_path = os.path.join(os.path.dirname(abs_path), new_name)
    if not new_abs_path.startswith(os.path.abspath("scripts")):
        return JSONResponse({"error": "无效新路径"}, status_code=400)
    try:
        os.rename(abs_path, new_abs_path)
        return {"message": "重命名成功"}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False, reload_dirs=["templates", "static"])
