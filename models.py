from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, ForeignKey, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at = Column(DateTime, default=datetime.now)

class Script(Base):
    __tablename__ = "scripts"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    filename = Column(String(255), nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    files = relationship("ScriptFile", back_populates="script", cascade="all, delete-orphan")
    tasks = relationship("Task", back_populates="script")

class ScriptFile(Base):
    __tablename__ = "script_files"

    id = Column(Integer, primary_key=True, index=True)
    script_id = Column(Integer, ForeignKey("scripts.id", ondelete="CASCADE"))
    filename = Column(String)
    original_filename = Column(String)  # 原始文件名
    file_type = Column(String)  # 文件类型/扩展名
    description = Column(String, nullable=True)  # 可选的描述
    created_at = Column(DateTime, default=datetime.now)
    script = relationship("Script", back_populates="files")

class Task(Base):
    __tablename__ = "tasks"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    script_id = Column(Integer, ForeignKey("scripts.id"))
    cron_expression = Column(String(100), nullable=False)  # 例如: "0 0 * * *"
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.now)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    
    script = relationship("Script", back_populates="tasks")
    logs = relationship("TaskLog", back_populates="task")

class TaskLog(Base):
    __tablename__ = "task_logs"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(Integer, ForeignKey("tasks.id"), index=True)
    status = Column(String(20), nullable=False)  # success, failed, running
    output = Column(Text)
    error = Column(Text)
    started_at = Column(DateTime, default=datetime.now, index=True)
    finished_at = Column(DateTime, nullable=True)
    
    task = relationship("Task", back_populates="logs")

class EnvironmentVariable(Base):
    __tablename__ = "environment_variables"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True, nullable=False)
    value = Column(Text) # 使用Text存储可能很长的值
    created_at = Column(DateTime, default=datetime.now)  # 添加创建时间字段

# 添加Session模型用于持久会话
class Session(Base):
    __tablename__ = "sessions"

    id = Column(String, primary_key=True, index=True)
    username = Column(String, ForeignKey("users.username"), index=True)
    expires = Column(DateTime, index=True)

    user = relationship("User")

class AppSetting(Base):
    """系统级配置（数据维护、执行策略等），与环境变量表隔离，避免污染脚本运行环境。"""
    __tablename__ = "app_settings"

    key = Column(String(100), primary_key=True)
    value = Column(Text)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

# 创建数据库引擎
# timeout：SQLite 写锁等待秒数，避免多线程/调度器/子进程并发写入时立刻抛 "database is locked"
engine = create_engine(
    "sqlite:///beeline.db",
    connect_args={"timeout": 30, "check_same_thread": False},
    future=True,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    """每条连接建立时统一 PRAGMA。

    - journal_mode=WAL：读写并发不互斥，降低 Web 请求与调度任务之间的锁冲突
    - synchronous=NORMAL：WAL 下兼顾安全与性能
    - busy_timeout：写锁等待 30 秒，超出才报错
    - foreign_keys：显式开启外键约束
    """
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA foreign_keys=ON")
    except Exception:
        pass
    finally:
        cursor.close()

# 创建所有表
Base.metadata.create_all(bind=engine)
