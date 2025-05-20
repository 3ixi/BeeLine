from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
from passlib.context import CryptContext

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

class Script(Base):
    __tablename__ = "scripts"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    filename = Column(String(255), nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.now)
    tasks = relationship("Task", back_populates="script")

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
    task_id = Column(Integer, ForeignKey("tasks.id"))
    status = Column(String(20), nullable=False)  # success, failed, running
    output = Column(Text)
    error = Column(Text)
    started_at = Column(DateTime, default=datetime.now)
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
    expires = Column(DateTime)

    user = relationship("User")

# 创建数据库引擎
engine = create_engine("sqlite:///beeline.db")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 创建所有表
Base.metadata.create_all(bind=engine) 