"""数据维护模块：日志保留策略、空间回收与数据库体积监控。

设计要点
--------
1. SQLite 的 DELETE 只是把页放入 freelist，物理文件不会自动缩小，
   因此清理之后必须显式回收空间（增量 VACUUM 或全量 VACUUM）。
2. 清理分三档：按时间保留 -> 按任务条数保留 -> 超过体积阈值时按最旧顺序激进删除。
3. 所有写操作使用独立的 sqlite3 连接并分批提交，避免长事务阻塞 Web 请求与任务执行。
4. 同一时间只允许一个维护任务运行（MAINTENANCE_LOCK）。
"""

import os
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from models import AppSetting, SessionLocal, engine

# 数据库文件的实际路径（与 models.py 中的 sqlite:///beeline.db 保持一致）
DB_FILE = os.path.abspath(engine.url.database)

# 维护互斥锁：清理与压缩串行执行，避免 VACUUM 与任务写入相互阻塞
MAINTENANCE_LOCK = threading.Lock()

CLEANUP_JOB_ID = "__maintenance__"

# 默认配置。值统一以字符串入库，读取时按类型转换。
DEFAULTS: Dict[str, str] = {
    "cleanup.enabled": "true",
    "cleanup.log_retention_days": "30",
    "cleanup.max_logs_per_task": "200",
    "cleanup.max_output_kb": "256",
    "cleanup.run_hour": "3",
    "cleanup.max_db_size_mb": "0",
    "cleanup.vacuum_mode": "incremental",
    "execution.timeout_seconds": "3600",
    "cleanup.last_run": "",
    "cleanup.last_result": "",
}

# 允许通过接口修改的键及其取值约束 (最小值, 最大值)
NUMERIC_RULES = {
    "cleanup.log_retention_days": (0, 3650),
    "cleanup.max_logs_per_task": (0, 1000000),
    "cleanup.max_output_kb": (0, 10485760),
    "cleanup.run_hour": (0, 23),
    "cleanup.max_db_size_mb": (0, 1048576),
    "execution.timeout_seconds": (0, 604800),
}

EDITABLE_KEYS = set(NUMERIC_RULES) | {"cleanup.enabled", "cleanup.vacuum_mode"}


# --------------------------------------------------------------------------- #
# 配置读写
# --------------------------------------------------------------------------- #
def load_settings() -> Dict[str, str]:
    """读取全部配置（缺失项用默认值补全）。线程安全，内部自建会话。"""
    db = SessionLocal()
    try:
        rows = db.query(AppSetting).all()
        stored = {r.key: r.value for r in rows if r.value is not None}
    finally:
        db.close()
    merged = dict(DEFAULTS)
    merged.update({k: v for k, v in stored.items() if v is not None})
    return merged


def _to_bool(value: str) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def get_int(key: str, default: int = 0) -> int:
    raw = load_settings().get(key, str(default))
    try:
        return int(float(raw))
    except (TypeError, ValueError):
        return default


def get_bool(key: str, default: bool = False) -> bool:
    raw = load_settings().get(key)
    return default if raw is None else _to_bool(raw)


def get_execution_timeout() -> int:
    """脚本执行超时（秒），0 表示不限制。"""
    return get_int("execution.timeout_seconds", 3600)


def get_max_output_kb() -> int:
    """单条日志输出上限（KB），0 表示不截断。"""
    return get_int("cleanup.max_output_kb", 256)


def _normalize(key: str, raw: Any) -> str:
    """校验并规范化单个配置值，非法值抛 ValueError。"""
    if key == "cleanup.enabled":
        return "true" if (raw is True or str(raw).strip().lower() in ("1", "true", "yes", "on")) else "false"
    if key == "cleanup.vacuum_mode":
        mode = str(raw).strip().lower()
        if mode not in ("incremental", "full", "none"):
            raise ValueError("压缩模式仅支持 incremental / full / none")
        return mode
    if key in NUMERIC_RULES:
        low, high = NUMERIC_RULES[key]
        try:
            value = int(str(raw).strip())
        except (TypeError, ValueError):
            raise ValueError(f"{key} 必须是整数")
        if value < low or value > high:
            raise ValueError(f"{key} 取值范围为 {low} ~ {high}")
        return str(value)
    raise ValueError(f"未知配置项: {key}")


def save_settings(updates: Dict[str, Any]) -> Dict[str, str]:
    """批量保存配置，返回规范化后的完整配置。"""
    cleaned: Dict[str, str] = {}
    for key, value in updates.items():
        if key not in EDITABLE_KEYS:
            continue
        cleaned[key] = _normalize(key, value)

    db = SessionLocal()
    try:
        for key, value in cleaned.items():
            row = db.query(AppSetting).filter(AppSetting.key == key).first()
            if row:
                row.value = value
            else:
                db.add(AppSetting(key=key, value=value))
        db.commit()
    finally:
        db.close()
    return load_settings()


def settings_for_ui() -> Dict[str, Any]:
    """给前端使用的强类型配置。"""
    cfg = load_settings()

    def _int(key, default):
        try:
            return int(float(cfg.get(key, default)))
        except (TypeError, ValueError):
            return default

    return {
        "enabled": _to_bool(cfg.get("cleanup.enabled", "true")),
        "log_retention_days": _int("cleanup.log_retention_days", 30),
        "max_logs_per_task": _int("cleanup.max_logs_per_task", 200),
        "max_output_kb": _int("cleanup.max_output_kb", 256),
        "run_hour": _int("cleanup.run_hour", 3),
        "max_db_size_mb": _int("cleanup.max_db_size_mb", 0),
        "vacuum_mode": cfg.get("cleanup.vacuum_mode", "incremental"),
        "execution_timeout_seconds": _int("execution.timeout_seconds", 3600),
        "last_run": cfg.get("cleanup.last_run", ""),
        "last_result": cfg.get("cleanup.last_result", ""),
    }


# --------------------------------------------------------------------------- #
# 日志写入侧收敛：避免单条日志把数据库撑大
# --------------------------------------------------------------------------- #
def truncate_text(text: Optional[str], max_kb: Optional[int] = None) -> Optional[str]:
    """按配置截断超长输出，保留头尾关键信息并标注省略量。"""
    if not text:
        return text
    limit_kb = get_max_output_kb() if max_kb is None else max_kb
    if limit_kb <= 0:
        return text
    limit = limit_kb * 1024
    if len(text) <= limit:
        return text
    head_len = int(limit * 0.6)
    tail_len = int(limit * 0.3)
    head = text[:head_len]
    tail = text[-tail_len:] if tail_len > 0 else ""
    omitted = len(text) - len(head) - len(tail)
    marker = f"\n\n... [BeeLine 已省略 {omitted} 个字符，原始长度 {len(text)}，上限 {limit_kb} KB] ...\n\n"
    return f"{head}{marker}{tail}"


# --------------------------------------------------------------------------- #
# 统计
# --------------------------------------------------------------------------- #
def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE, timeout=30, isolation_level=None)
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _table_count(conn: sqlite3.Connection, table: str) -> int:
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    except sqlite3.Error:
        return 0


def db_stats() -> Dict[str, Any]:
    """返回数据库体积、表行数与可回收空间。"""
    stats: Dict[str, Any] = {
        "db_path": DB_FILE,
        "db_size": _file_size(DB_FILE),
        "wal_size": _file_size(DB_FILE + "-wal"),
        "shm_size": _file_size(DB_FILE + "-shm"),
        "page_size": 0,
        "page_count": 0,
        "freelist_count": 0,
        "reclaimable": 0,
        "auto_vacuum": 0,
        "journal_mode": "",
        "tables": {},
        "last_run": "",
        "last_result": "",
    }
    try:
        conn = _connect()
    except sqlite3.Error as exc:
        stats["error"] = str(exc)
        return stats
    try:
        stats["page_size"] = conn.execute("PRAGMA page_size").fetchone()[0]
        stats["page_count"] = conn.execute("PRAGMA page_count").fetchone()[0]
        stats["freelist_count"] = conn.execute("PRAGMA freelist_count").fetchone()[0]
        stats["auto_vacuum"] = conn.execute("PRAGMA auto_vacuum").fetchone()[0]
        stats["journal_mode"] = conn.execute("PRAGMA journal_mode").fetchone()[0]
        stats["reclaimable"] = stats["page_size"] * stats["freelist_count"]
        for table in (
            "task_logs", "tasks", "scripts", "script_files",
            "environment_variables", "sessions", "users", "app_settings", "apscheduler_jobs",
        ):
            stats["tables"][table] = _table_count(conn, table)
    except sqlite3.Error as exc:
        stats["error"] = str(exc)
    finally:
        conn.close()

    cfg = settings_for_ui()
    stats["last_run"] = cfg["last_run"]
    stats["last_result"] = cfg["last_result"]
    return stats


# --------------------------------------------------------------------------- #
# 清理与回收
# --------------------------------------------------------------------------- #
def _batch_delete(conn: sqlite3.Connection, inner_select: str, params: tuple = (), chunk: int = 5000) -> int:
    """按 id 分批删除，inner_select 必须是只返回 id 的 SELECT。"""
    total = 0
    while True:
        sql = f"DELETE FROM task_logs WHERE id IN (SELECT id FROM ({inner_select}) LIMIT {chunk})"
        try:
            cur = conn.execute(sql, params)
            deleted = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        except sqlite3.Error:
            return total
        total += deleted
        if deleted == 0:
            break
    return total


def _delete_simple(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> int:
    try:
        cur = conn.execute(sql, params)
        return cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
    except sqlite3.Error:
        return 0


def _dt(value: datetime) -> str:
    """与 SQLAlchemy 存入 SQLite 的时间格式保持一致，便于字符串比较。"""
    return value.strftime("%Y-%m-%d %H:%M:%S.%f")


def vacuum(mode: Optional[str] = None) -> Dict[str, Any]:
    """回收物理空间。incremental 需 auto_vacuum=INCREMENTAL 生效。"""
    mode = mode or load_settings().get("cleanup.vacuum_mode", "incremental")
    if mode == "none":
        return {"mode": "none", "before": _file_size(DB_FILE), "after": _file_size(DB_FILE), "freed": 0}

    acquired = MAINTENANCE_LOCK.acquire(timeout=1)
    if not acquired:
        return {"mode": mode, "skipped": True, "reason": "另一个维护任务正在执行"}
    try:
        before = _file_size(DB_FILE)
        conn = _connect()
        try:
            actual = mode
            if mode == "incremental":
                auto_vacuum = conn.execute("PRAGMA auto_vacuum").fetchone()[0]
                if auto_vacuum != 2:
                    # 尚未迁移到增量模式，退化执行一次全量 VACUUM 以完成迁移
                    conn.execute("VACUUM").fetchall()
                    actual = "full(首次迁移)"
                else:
                    # incremental_vacuum 每释放一页返回一行，必须完整取回结果集才会释放全部空闲页
                    for _ in range(5):
                        freed_rows = conn.execute("PRAGMA incremental_vacuum").fetchall()
                        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
                        if not freed_rows:
                            break
                        if conn.execute("PRAGMA freelist_count").fetchone()[0] == 0:
                            break
            else:
                conn.execute("VACUUM").fetchall()
            # 把 WAL 内容合并回主库并截断，否则 -wal 文件会维持峰值体积
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        finally:
            conn.close()
        after = _file_size(DB_FILE)
        return {"mode": actual, "before": before, "after": after, "freed": max(0, before - after)}
    finally:
        MAINTENANCE_LOCK.release()


def run_cleanup(trigger: str = "manual", vacuum_after: Optional[bool] = None) -> Dict[str, Any]:
    """执行一轮清理。

    参数
    ----
    trigger: manual / scheduled / auto（仅用于记录）
    vacuum_after: 是否在清理后回收空间，None 表示按配置的 vacuum_mode 决定
    """
    if not MAINTENANCE_LOCK.acquire(blocking=False):
        return {"ok": False, "skipped": True, "message": "已有维护任务在执行，请稍后重试"}

    cfg = settings_for_ui()
    started = datetime.now()
    report: Dict[str, Any] = {
        "ok": True,
        "trigger": trigger,
        "started_at": started.strftime("%Y-%m-%d %H:%M:%S"),
        "deleted_expired_logs": 0,
        "deleted_overflow_logs": 0,
        "deleted_orphan_logs": 0,
        "deleted_oversize_logs": 0,
        "deleted_sessions": 0,
        "deleted_orphan_files": 0,
        "deleted_stale_jobs": 0,
        "size_before": _file_size(DB_FILE),
        "size_after": 0,
        "freed": 0,
        "vacuum": "none",
        "notes": [],
    }

    conn = None
    try:
        if trigger == "scheduled" and not cfg["enabled"]:
            return {"ok": True, "skipped": True, "message": "自动清理已关闭"}

        conn = _connect()
        now = datetime.now()

        # 1. 按天保留
        days = cfg["log_retention_days"]
        if days > 0:
            cutoff = now - timedelta(days=days)
            report["deleted_expired_logs"] = _batch_delete(
                conn,
                "SELECT id FROM task_logs WHERE started_at < ? AND status != 'running'",
                (_dt(cutoff),),
            )

        # 2. 每任务条数上限
        keep = cfg["max_logs_per_task"]
        if keep > 0:
            try:
                report["deleted_overflow_logs"] = _delete_simple(
                    conn,
                    """
                    DELETE FROM task_logs WHERE id IN (
                        SELECT id FROM (
                            SELECT id, ROW_NUMBER() OVER (
                                PARTITION BY task_id ORDER BY started_at DESC, id DESC
                            ) AS rn
                            FROM task_logs WHERE status != 'running'
                        ) WHERE rn > ?
                    )
                    """,
                    (keep,),
                )
            except sqlite3.Error as exc:
                report["notes"].append(f"窗口函数不可用，已跳过按任务条数清理: {exc}")

        # 3. 孤立日志（任务已被删除）
        report["deleted_orphan_logs"] = _delete_simple(
            conn, "DELETE FROM task_logs WHERE task_id NOT IN (SELECT id FROM tasks)"
        )

        # 4. 过期会话
        report["deleted_sessions"] = _delete_simple(
            conn, "DELETE FROM sessions WHERE expires IS NOT NULL AND expires < ?", (_dt(now),)
        )

        # 5. 孤立附件记录
        report["deleted_orphan_files"] = _delete_simple(
            conn, "DELETE FROM script_files WHERE script_id NOT IN (SELECT id FROM scripts)"
        )

        # 6. 调度器里残留的已删除任务
        report["deleted_stale_jobs"] = _delete_simple(
            conn,
            """
            DELETE FROM apscheduler_jobs
            WHERE id LIKE 'task\\_%' ESCAPE '\\'
              AND CAST(SUBSTR(id, 6) AS INTEGER) NOT IN (SELECT id FROM tasks)
            """,
        )

        # 7. 体积阈值：超过上限时按最旧顺序继续删除
        max_bytes = cfg["max_db_size_mb"] * 1024 * 1024
        if max_bytes > 0:
            guard = 0
            while _file_size(DB_FILE) > max_bytes and guard < 200:
                guard += 1
                deleted = _batch_delete(
                    conn,
                    "SELECT id FROM task_logs WHERE status != 'running' ORDER BY started_at ASC",
                    (),
                    2000,
                )
                report["deleted_oversize_logs"] += deleted
                if deleted == 0:
                    report["notes"].append("日志已清空但仍超出体积阈值，请检查脚本与附件占用")
                    break
                if guard % 20 == 0:
                    conn.execute("PRAGMA incremental_vacuum").fetchall()

        conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchall()
    except Exception as exc:
        report["ok"] = False
        report["notes"].append(f"清理过程出错: {exc}")
    finally:
        if conn is not None:
            conn.close()
        MAINTENANCE_LOCK.release()

    # 空间回收（独立加锁流程）
    if vacuum_after is None:
        vacuum_after = cfg["vacuum_mode"] != "none"
    if vacuum_after:
        try:
            vac = vacuum(cfg["vacuum_mode"])
            report["vacuum"] = vac.get("mode", cfg["vacuum_mode"])
            if vac.get("skipped"):
                report["notes"].append(vac.get("reason", ""))
        except Exception as exc:
            report["notes"].append(f"空间回收失败: {exc}")
            report["vacuum"] = "failed"

    report["size_after"] = _file_size(DB_FILE)
    report["freed"] = max(0, report["size_before"] - report["size_after"])
    report["elapsed_ms"] = int((datetime.now() - started).total_seconds() * 1000)

    summary = (
        f"删除日志 {report['deleted_expired_logs'] + report['deleted_overflow_logs'] + report['deleted_orphan_logs'] + report['deleted_oversize_logs']} 条，"
        f"会话 {report['deleted_sessions']} 条，回收 {report['freed'] / 1024 / 1024:.2f} MB，耗时 {report['elapsed_ms']} ms"
    )
    try:
        db = SessionLocal()
        try:
            for key, value in (
                ("cleanup.last_run", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                ("cleanup.last_result", summary),
            ):
                row = db.query(AppSetting).filter(AppSetting.key == key).first()
                if row:
                    row.value = value
                else:
                    db.add(AppSetting(key=key, value=value))
            db.commit()
        finally:
            db.close()
    except Exception:
        pass

    report["summary"] = summary
    return report


# --------------------------------------------------------------------------- #
# 启动初始化与调度注册
# --------------------------------------------------------------------------- #
def ensure_storage() -> None:
    """启动时的一次性迁移：切换 WAL、启用增量回收、补齐索引。

    切换 auto_vacuum 需要重建数据库文件，大库会耗时可观，因此由调用方放在后台线程执行。
    """
    if not os.path.exists(DB_FILE):
        return
    if not MAINTENANCE_LOCK.acquire(blocking=False):
        return
    try:
        conn = _connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            auto_vacuum = conn.execute("PRAGMA auto_vacuum").fetchone()[0]
            if auto_vacuum != 2:
                # auto_vacuum 只能在 VACUUM 时生效，此操作重建整个数据库文件
                conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
                conn.execute("VACUUM").fetchall()
                print("[maintenance] 已迁移至增量回收模式 (auto_vacuum=INCREMENTAL)")
            for sql in (
                "CREATE INDEX IF NOT EXISTS ix_task_logs_task_started ON task_logs(task_id, started_at)",
                "CREATE INDEX IF NOT EXISTS ix_task_logs_started_at ON task_logs(started_at)",
                "CREATE INDEX IF NOT EXISTS ix_sessions_expires ON sessions(expires)",
            ):
                conn.execute(sql)
        finally:
            conn.close()
    except Exception as exc:
        print(f"[maintenance] 存储初始化失败: {exc}")
    finally:
        MAINTENANCE_LOCK.release()


def cleanup_scheduled_job() -> None:
    """APScheduler 入口。"""
    try:
        result = run_cleanup(trigger="scheduled")
        if not result.get("skipped"):
            print(f"[maintenance] 定时清理完成: {result.get('summary')}")
    except Exception as exc:
        print(f"[maintenance] 定时清理失败: {exc}")


def register_cleanup_job(scheduler) -> bool:
    """按配置注册/更新每日清理任务。返回是否处于启用状态。"""
    cfg = settings_for_ui()
    try:
        if not cfg["enabled"]:
            try:
                scheduler.remove_job(CLEANUP_JOB_ID)
            except Exception:
                pass
            return False
        scheduler.add_job(
            cleanup_scheduled_job,
            "cron",
            hour=cfg["run_hour"],
            minute=0,
            id=CLEANUP_JOB_ID,
            replace_existing=True,
            coalesce=True,
            misfire_grace_time=3600,
        )
        return True
    except Exception as exc:
        print(f"[maintenance] 注册清理任务失败: {exc}")
        return False
