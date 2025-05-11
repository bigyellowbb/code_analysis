from sqlalchemy import Column, Integer, String, Text, Boolean, ForeignKey, DateTime, Index
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from typing import Optional

Base = declarative_base()

class User(Base):
    """用户表"""
    __tablename__ = "user"

    user_id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(60), unique=True, index=True, nullable=False)
    password = Column(String(128), nullable=False)  # 存储加密后的密码
    email = Column(String(120), unique=True, index=True, nullable=False)
    phone = Column(String(20))
    # is_active = Column(Boolean, default=True)
    created_at = Column(String(60), default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # 关系
    # projects = relationship("Project", back_populates="owner")
    # questions = relationship("Question", back_populates="user")

# class Project(Base):
#     """项目表"""
#     __tablename__ = "project"
#
#     project_id = Column(Integer, primary_key=True, autoincrement=True)
#     user_id = Column(Integer, ForeignKey("user.user_id", ondelete="CASCADE"), nullable=False)
#     name = Column(String(100), nullable=False)
#     description = Column(Text)
#     created_at = Column(String(60), default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
#
#     # 关系
#     owner = relationship("User", back_populates="projects")
#     code_files = relationship("CodeFile", back_populates="project")
#     analyses = relationship("ProjectAnalysis", back_populates="project")

class CodeFile(Base):
    """代码文件表"""
    __tablename__ = "codefile"

    code_file_id = Column(Integer, primary_key=True, autoincrement=True)
    # project_id = Column(Integer, ForeignKey("project.project_id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("user.user_id", ondelete="CASCADE"), nullable=False)
    file_name = Column(String(255), nullable=False)
    file_path = Column(String(512))
    content_hash = Column(String(64))  # 文件内容哈希值
    is_active_conversation = Column(Boolean, default=True)
    created_at = Column(String(60), default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # 关系
    # project = relationship("Project", back_populates="code_files")
    analyses = relationship("CodeAnalysis", back_populates="code_file")
    # questions = relationship("Question", back_populates="code_file")
    conversations = relationship("Conversation", back_populates="code_file")


class CodeAnalysis(Base):
    """代码分析表"""
    __tablename__ = "code_analysis"

    analysis_id = Column(Integer, primary_key=True, autoincrement=True)
    code_file_id = Column(Integer, ForeignKey("codefile.code_file_id", ondelete="CASCADE"), nullable=False)
    analysis_type = Column(String(50), nullable=False)  # full/security/performance等
    summary = Column(Text)
    raw_results = Column(Text, default="{}")
    created_at = Column(String(60), default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # 关系
    code_file = relationship("CodeFile", back_populates="analyses")
    issues = relationship("AnalysisIssue", back_populates="analysis")

class AnalysisIssue(Base):
    """分析问题表"""
    __tablename__ = "analysis_issue"

    issue_id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(Integer, ForeignKey("code_analysis.analysis_id", ondelete="CASCADE"), nullable=False)
    file_path = Column(String(512), nullable=False)  # 问题所在文件路径
    severity = Column(String(20), nullable=False)  # critical/high/medium/low
    category = Column(String(50), nullable=False)  # security/performance等
    description = Column(Text, nullable=False)
    recommendation = Column(Text)
    line_number = Column(Integer)  # 问题所在行号
    status = Column(String(20), default="open")  # open/fixed/ignored
    created_at = Column(String(60), default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # 关系
    analysis = relationship("CodeAnalysis", back_populates="issues")


class Conversation(Base):
    __tablename__ = "conversation"

    conversation_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("user.user_id", ondelete="CASCADE"), nullable=False)
    code_file_id = Column(Integer, ForeignKey("codefile.code_file_id", ondelete="CASCADE"), nullable=False)

    # 消息相关字段
    role = Column(String(20))  # user/assistant
    content = Column(Text)
    created_at = Column(String(60), default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    is_active = True
    user = relationship("User")
    code_file = relationship("CodeFile", back_populates="conversations")

# class Question(Base):
#     """问题表"""
#     __tablename__ = "question"
#
#     question_id = Column(Integer, primary_key=True, autoincrement=True)
#     code_file_id = Column(Integer, ForeignKey("codefile.code_file_id", ondelete="CASCADE"), nullable=False)
#     user_id = Column(Integer, ForeignKey("user.user_id", ondelete="CASCADE"), nullable=False)
#     question_text = Column(Text, nullable=False)
#     created_at = Column(String(60), default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
#
#     # 关系
#     code_file = relationship("CodeFile", back_populates="questions")
#     user = relationship("User", back_populates="questions")
#     answers = relationship("Answer", back_populates="question")
#
# class Answer(Base):
#     """回答表"""
#     __tablename__ = "answer"
#
#     answer_id = Column(Integer, primary_key=True, autoincrement=True)
#     question_id = Column(Integer, ForeignKey("question.question_id", ondelete="CASCADE"), nullable=False)
#     answer_text = Column(Text, nullable=False)
#     created_at = Column(String(60), default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
#
#     # 关系
#     question = relationship("Question", back_populates="answers")

# class ProjectAnalysis(Base):
#     """项目分析表"""
#     __tablename__ = "project_analysis"
#
#     project_analysis_id = Column(Integer, primary_key=True, autoincrement=True)
#     project_id = Column(Integer, ForeignKey("project.project_id", ondelete="CASCADE"), nullable=False)
#     analysis_type = Column(String(50), nullable=False)
#     summary = Column(Text)
#     created_at = Column(String(60), default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
#
#     # 关系
#     project = relationship("Project", back_populates="analyses")