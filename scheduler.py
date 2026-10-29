from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.executors.pool import ThreadPoolExecutor
from datetime import datetime
from collections import deque
import os
import sys
import subprocess
import threading

from models import SessionLocal, Task, TaskLog, Script
from maintenance import (
    get_execution_timeout,
    register_cleanup_job,
    truncate_text,
)

# 脚本工作目录（绝对路径，避免不同启动目录导致的相对路径歧义）
SCRIPTS_DIR = os.path.abspath("scripts")

# 运行中的任务登记表：Web 手动触发与定时触发共用同一份，防止同一任务重叠执行
# 值为 RunHandle，可从中取出进程句柄用于停止
running_tasks = {}
_run_lock = threading.Lock()

# 存储环境变量（全进程唯一实例，main.py 直接引用本字典，不得再重新定义）
env_vars = {}

# 单次运行保留在内存中的输出上限（字符）。DB 落库时还会按配置再截断一次。
BUFFER_LIMIT = 2 * 1024 * 1024

# 实时日志刷盘间隔（秒）
FLUSH_INTERVAL = 1.5


class RunHandle:
    """一次任务运行的运行时状态：进程句柄、停止信号与增量输出缓冲。"""

    def __init__(self, task_id):
        self.task_id = task_id
        self.log_id = None
        self.process = None
        self.started_at = datetime.now()
        self.cancel = threading.Event()
        self._lock = threading.Lock()
        self._buf = {"stdout": deque(), "stderr": deque()}
        self._len = {"stdout": 0, "stderr": 0}
        self._dropped = {"stdout": 0, "stderr": 0}
        self._last_written = {"stdout": None, "stderr": None}

    def attach(self, process):
        self.process = process

    def append(self, kind, text):
        if not text:
            return
        with self._lock:
            self._buf[kind].append(text)
            self._len[kind] += len(text)
            # 防止内存无限增长：超出上限时丢弃最早的片段
            while self._len[kind] > BUFFER_LIMIT and self._buf[kind]:
                dropped = self._buf[kind].popleft()
                self._len[kind] -= len(dropped)
                self._dropped[kind] += len(dropped)

    def snapshot(self, kind):
        with self._lock:
            text = "".join(self._buf[kind])
            dropped = self._dropped[kind]
        if dropped:
            text = f"... [内存缓冲已丢弃最早的 {dropped} 个字符] ...\n" + text
        return text

    def has_new_output(self):
        """与上次落库内容比较，避免无变化时反复写库。"""
        current = (self.snapshot("stdout"), self.snapshot("stderr"))
        changed = (
            current[0] != self._last_written["stdout"]
            or current[1] != self._last_written["stderr"]
        )
        if changed:
            self._last_written["stdout"], self._last_written["stderr"] = current
        return changed, current

    def elapsed_seconds(self):
        return max(0, int((datetime.now() - self.started_at).total_seconds()))

    def request_stop(self):
        self.cancel.set()
        if self.process is not None:
            _terminate_process(self.process)


def is_task_running(task_id) -> bool:
    with _run_lock:
        return task_id in running_tasks


def list_running_tasks():
    """返回正在运行的任务快照，供前端渲染“停止”按钮与实时日志入口。"""
    with _run_lock:
        handles = list(running_tasks.values())
    return [
        {
            "task_id": handle.task_id,
            "log_id": handle.log_id,
            "started_at": handle.started_at.strftime("%Y-%m-%d %H:%M:%S"),
            "elapsed_seconds": handle.elapsed_seconds(),
            "stopping": handle.cancel.is_set(),
        }
        for handle in handles
    ]


def stop_task(task_id) -> bool:
    """请求停止任务。返回是否找到正在运行的实例。"""
    with _run_lock:
        handle = running_tasks.get(task_id)
    if not handle:
        return False
    handle.request_stop()
    return True


def get_job_id(task_id):
    return f"task_{task_id}"


def _terminate_process(process):
    """终止进程。Windows 下子进程可能自行派生子进程，需整棵树一起结束。"""
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                capture_output=True,
                timeout=15,
            )
        else:
            process.kill()
    except Exception:
        try:
            process.kill()
        except Exception:
            pass


def _pump(pipe, handle, kind):
    """按块读取子进程输出，立即进入内存缓冲，供前端实时查看。

    使用二进制管道 + os.read，避免文本模式按行/按块阻塞导致输出迟迟不落库。
    """
    try:
        fd = pipe.fileno()
    except Exception:
        return
    while True:
        try:
            chunk = os.read(fd, 4096)
        except (OSError, ValueError):
            break
        if not chunk:
            break
        handle.append(kind, chunk.decode("utf-8", errors="replace"))
    try:
        pipe.close()
    except Exception:
        pass


def _flush_log(db, log_id, handle, status=None, final=False):
    """把缓冲中的输出写入数据库。运行中定期调用，结束时做最终落库。"""
    changed, (out_text, err_text) = handle.has_new_output()
    if not changed and not final:
        return
    try:
        log = db.query(TaskLog).filter(TaskLog.id == log_id).first()
        if not log:
            return
        log.output = truncate_text(out_text)
        log.error = truncate_text(err_text)
        if final:
            log.status = status or log.status
            log.finished_at = datetime.now()
        db.commit()
    except Exception as exc:
        print(f"[scheduler] 写入任务日志失败: {exc}")
        try:
            db.rollback()
        except Exception:
            pass


def run_script(task_id):
    """执行一次任务。同一 task_id 同一时刻只允许一个实例运行，运行中可被停止。"""
    handle = RunHandle(task_id)
    with _run_lock:
        if task_id in running_tasks:
            print(f"[scheduler] 任务 {task_id} 正在运行，本次触发已跳过。")
            return
        running_tasks[task_id] = handle

    db_thread = SessionLocal()
    log_id = None
    try:
        task_thread = db_thread.query(Task).filter(Task.id == task_id).first()
        script_thread = None
        if task_thread and task_thread.script_id:
            script_thread = db_thread.query(Script).filter(Script.id == task_thread.script_id).first()

        task_log = TaskLog(task_id=task_id, status="running")
        db_thread.add(task_log)
        db_thread.commit()
        db_thread.refresh(task_log)
        log_id = task_log.id
        handle.log_id = log_id

        if not task_thread:
            _flush_log(db_thread, log_id, handle, status="failed", final=True)
            _set_error(db_thread, log_id, "任务不存在或已被删除")
            return
        if not script_thread:
            _flush_log(db_thread, log_id, handle, status="failed", final=True)
            _set_error(db_thread, log_id, "任务关联的脚本不存在或已被删除")
            return

        script_path = os.path.join(SCRIPTS_DIR, script_thread.filename)
        if not os.path.isfile(script_path):
            _flush_log(db_thread, log_id, handle, status="failed", final=True)
            _set_error(db_thread, log_id, f"脚本文件不存在: {script_path}")
            return

        # 准备子进程环境变量：系统环境 + 用户自定义变量
        subprocess_env = os.environ.copy()
        subprocess_env.update(env_vars)
        subprocess_env["PYTHONIOENCODING"] = "utf-8"
        # 关键：关闭子进程自身缓冲，否则 print 的内容会攒到进程结束才输出
        subprocess_env["PYTHONUNBUFFERED"] = "1"

        process = subprocess.Popen(
            [sys.executable, "-u", script_thread.filename],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=subprocess_env,
            cwd=SCRIPTS_DIR,
        )
        handle.attach(process)

        # 若在进程创建前就收到了停止指令，立即终止，避免“停了还在跑”
        if handle.cancel.is_set():
            _terminate_process(process)

        readers = [
            threading.Thread(target=_pump, args=(process.stdout, handle, "stdout"), daemon=True),
            threading.Thread(target=_pump, args=(process.stderr, handle, "stderr"), daemon=True),
        ]
        for reader in readers:
            reader.start()

        timeout = get_execution_timeout()
        deadline = handle.started_at.timestamp() + timeout if timeout > 0 else None

        status = None
        timed_out = False
        while True:
            if handle.cancel.is_set():
                _terminate_process(process)
                status = "stopped"
                break
            try:
                process.wait(timeout=FLUSH_INTERVAL)
                break
            except subprocess.TimeoutExpired:
                _flush_log(db_thread, log_id, handle)  # 运行中实时落库
                if deadline is not None and datetime.now().timestamp() > deadline:
                    timed_out = True
                    _terminate_process(process)
                    status = "failed"
                    break
            except Exception:
                break

        # 等待读取线程收尾，确保末尾输出不丢失
        for reader in readers:
            reader.join(timeout=5)

        for _ in range(5):
            try:
                process.wait(timeout=1)
                break
            except subprocess.TimeoutExpired:
                continue

        returned_code = process.returncode
        # taskkill 会让 wait() 正常返回，因此需要在结束后再确认一次“是否由用户主动停止”
        if handle.cancel.is_set():
            status = "stopped"
        elif status is None:
            status = "success" if returned_code == 0 else "failed"

        _flush_log(db_thread, log_id, handle, status=status, final=True)

        # 附加说明信息（超时/手动停止）
        if timed_out:
            _set_error(db_thread, log_id, f"执行超时（{timeout} 秒），进程已被强制终止。")
        elif status == "stopped":
            _set_error(db_thread, log_id, "任务被用户手动停止。")
        elif status == "failed" and returned_code not in (0, None):
            _set_error(db_thread, log_id, f"进程退出码: {returned_code}")

        # 更新任务运行时间与下次运行时间
        task_to_update = db_thread.query(Task).filter(Task.id == task_id).first()
        if task_to_update:
            task_to_update.last_run_at = datetime.now()
            if task_to_update.is_active and task_to_update.cron_expression:
                try:
                    import croniter as _croniter
                    cron = _croniter.croniter(task_to_update.cron_expression, datetime.now())
                    task_to_update.next_run_at = cron.get_next(datetime)
                except Exception as exc:
                    print(f"[scheduler] 计算任务 {task_id} 下次运行时间失败: {exc}")
            db_thread.commit()

    except Exception as e:
        print(f"[scheduler] 任务 {task_id} 执行异常: {e}")
        try:
            if log_id:
                _flush_log(db_thread, log_id, handle, status="failed", final=True)
                _set_error(db_thread, log_id, f"调度器异常: {e}")
        except Exception:
            try:
                db_thread.rollback()
            except Exception:
                pass
    finally:
        db_thread.close()
        with _run_lock:
            running_tasks.pop(task_id, None)


def _set_error(db, log_id, message):
    """向日志的 error 字段追加一条说明，保留已有的标准错误输出。"""
    try:
        log = db.query(TaskLog).filter(TaskLog.id == log_id).first()
        if not log:
            return
        prefix = (log.error or "").rstrip()
        log.error = truncate_text((prefix + "\n[BeeLine] " + message).strip())
        db.commit()
    except Exception as exc:
        print(f"[scheduler] 追加日志说明失败: {exc}")
        try:
            db.rollback()
        except Exception:
            pass


def reconcile_stale_logs():
    """启动时把遗留的 running 日志标记为中断。

    进程随服务重启而消失，若不处理，这些日志会永远停留在“运行中”，
    既误导用户，也会被清理策略跳过。
    """
    db = SessionLocal()
    try:
        stale = db.query(TaskLog).filter(TaskLog.status == "running").all()
        if not stale:
            return 0
        now = datetime.now()
        for log in stale:
            log.status = "failed"
            log.finished_at = now
            log.error = truncate_text(((log.error or "").rstrip() + "\n[BeeLine] 服务重启，任务执行已中断。").strip())
        db.commit()
        print(f"[scheduler] 已将 {len(stale)} 条遗留的运行中日志标记为中断。")
        return len(stale)
    except Exception as exc:
        print(f"[scheduler] 处理遗留运行中日志失败: {exc}")
        try:
            db.rollback()
        except Exception:
            pass
        return 0
    finally:
        db.close()


# 创建调度器
# engine_options 中的 timeout 用于避免 Web 请求与调度器争抢 SQLite 写锁时直接报错
jobstores = {
    "default": SQLAlchemyJobStore(
        url="sqlite:///beeline.db",
        engine_options={"connect_args": {"timeout": 30}},
    )
}

executors = {
    "default": ThreadPoolExecutor(20)
}

job_defaults = {
    "coalesce": True,       # 错过多次触发时只补一次，避免堆积
    "max_instances": 1,
}

scheduler = BackgroundScheduler(
    jobstores=jobstores,
    executors=executors,
    job_defaults=job_defaults,
    timezone="Asia/Shanghai"
)


def init_scheduler():
    """初始化调度器并加载所有活动的任务"""
    if not scheduler.running:
        # 先清理上次运行残留的“运行中”日志
        reconcile_stale_logs()

        scheduler.start()

        db = SessionLocal()
        try:
            active_tasks = db.query(Task).filter(Task.is_active == True).all()  # noqa: E712
            for task in active_tasks:
                if not task.script_id:
                    continue
                if not db.query(Script).filter(Script.id == task.script_id).first():
                    # 脚本已被删除，停用任务，避免每次触发都产生失败日志
                    task.is_active = False
                    db.commit()
                    continue
                add_job(task)
        finally:
            db.close()

        # 注册每日数据维护任务
        register_cleanup_job(scheduler)


def add_job(task):
    """添加或更新任务到调度器"""
    job_id = get_job_id(task.id)

    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    scheduler.add_job(
        run_script,
        "cron",
        args=[task.id],
        id=job_id,
        replace_existing=True,
        misfire_grace_time=300,
        **parse_cron_expression(task.cron_expression)
    )


def remove_job(task_id):
    """从调度器中移除任务"""
    job_id = get_job_id(task_id)
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)


def reload_jobs():
    """按数据库现状重建全部任务（用于备份导入、批量变更后）。"""
    try:
        for job in scheduler.get_jobs():
            if job.id.startswith("task_"):
                scheduler.remove_job(job.id)
    except Exception as exc:
        print(f"[scheduler] 清理旧任务失败: {exc}")

    db = SessionLocal()
    try:
        for task in db.query(Task).filter(Task.is_active == True).all():  # noqa: E712
            if not task.script_id:
                continue
            try:
                add_job(task)
            except Exception as exc:
                print(f"[scheduler] 重建任务 {task.id} 失败: {exc}")
    finally:
        db.close()

    register_cleanup_job(scheduler)


def parse_cron_expression(cron_expression):
    """解析cron表达式为APScheduler参数（仅支持标准 5 段格式）"""
    parts = str(cron_expression).split()
    if len(parts) != 5:
        raise ValueError("Cron 表达式必须是 5 段格式，例如 0 2 * * *")

    minute, hour, day, month, day_of_week = parts

    return {
        "minute": minute,
        "hour": hour,
        "day": day,
        "month": month,
        "day_of_week": day_of_week,
    }


def validate_cron_expression(cron_expression):
    """校验 cron 表达式，非法时抛 ValueError。"""
    parse_cron_expression(cron_expression)
    import croniter as _croniter
    if not _croniter.croniter.is_valid(cron_expression):
        raise ValueError("无效的 Cron 表达式")


def shutdown_scheduler():
    """关闭调度器。若有任务正在执行，先终止子进程再退出。"""
    with _run_lock:
        handles = list(running_tasks.values())
    for handle in handles:
        handle.request_stop()
    if scheduler.running:
        scheduler.shutdown()
