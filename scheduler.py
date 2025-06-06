from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.executors.pool import ThreadPoolExecutor
from datetime import datetime
import os
from models import SessionLocal, Task, TaskLog, Script
import subprocess
import threading

# 存储运行中的任务
running_tasks = {}

# 存储环境变量
env_vars = {}

def get_job_id(task_id):
    return f"task_{task_id}"

def run_script(task_id):
    db_thread = SessionLocal()
    try:
        # 在线程的数据库会话中创建任务日志
        task_log = TaskLog(
            task_id=task_id,
            status="running"
        )
        db_thread.add(task_log)
        db_thread.commit()
        db_thread.refresh(task_log)

        # 在线程的数据库会话中重新查询任务
        task_thread = db_thread.query(Task).filter(Task.id == task_id).first()
        if not task_thread:
            print(f"任务 {task_id} 未找到。")
            return

        # 在线程的数据库会话中重新查询脚本
        script_thread = db_thread.query(Script).filter(Script.id == task_thread.script_id).first()
        if not script_thread:
            print(f"任务 {task_id} 的脚本未找到。")
            return

        script_path = os.path.join("scripts", script_thread.filename)
        
        # 准备用于子进程的环境变量
        subprocess_env = os.environ.copy()
        subprocess_env.update(env_vars)
        subprocess_env['PYTHONIOENCODING'] = 'utf-8'  # 设置Python IO编码

        process = subprocess.Popen(
            ["python", script_path],
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
            db_thread.commit()

    except Exception as e:
        # 如果脚本执行失败，则记录错误
        log_to_update = db_thread.query(TaskLog).filter(TaskLog.task_id == task_id, TaskLog.status == "running").order_by(TaskLog.started_at.desc()).first()
        if log_to_update:
            log_to_update.status = "failed"
            log_to_update.error = str(e)
            log_to_update.finished_at = datetime.now()
            db_thread.commit()
        print(f"Error running task {task_id}: {e}")
    finally:
        db_thread.close()
        running_tasks.pop(task_id, None)

# 创建调度器
jobstores = {
    'default': SQLAlchemyJobStore(url='sqlite:///beeline.db')
}

executors = {
    'default': ThreadPoolExecutor(20)
}

job_defaults = {
    'coalesce': False,
    'max_instances': 1
}

scheduler = BackgroundScheduler(
    jobstores=jobstores,
    executors=executors,
    job_defaults=job_defaults,
    timezone='Asia/Shanghai'
)

def init_scheduler():
    """初始化调度器并加载所有活动的任务"""
    if not scheduler.running:
        scheduler.start()
        
        # 从数据库加载所有活动的任务
        db = SessionLocal()
        try:
            active_tasks = db.query(Task).filter(Task.is_active == True).all()
            for task in active_tasks:
                add_job(task)
        finally:
            db.close()

def add_job(task):
    """添加或更新任务到调度器"""
    job_id = get_job_id(task.id)
    
    # 如果任务已存在，先移除
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    
    # 添加新任务
    scheduler.add_job(
        run_script,
        'cron',
        args=[task.id],
        id=job_id,
        replace_existing=True,
        **parse_cron_expression(task.cron_expression)
    )

def remove_job(task_id):
    """从调度器中移除任务"""
    job_id = get_job_id(task_id)
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

def parse_cron_expression(cron_expression):
    """解析cron表达式为APScheduler参数"""
    parts = cron_expression.split()
    if len(parts) != 5:
        raise ValueError("无效的Cron表达式")
    
    minute, hour, day, month, day_of_week = parts
    
    return {
        'minute': minute,
        'hour': hour,
        'day': day,
        'month': month,
        'day_of_week': day_of_week
    }

def shutdown_scheduler():
    """关闭调度器"""
    if scheduler.running:
        scheduler.shutdown() 
