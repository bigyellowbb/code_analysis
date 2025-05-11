import asyncio
from pydantic.v1 import validator
from typing import Dict, List
from ..utils.file_utils import safe_read_file, safe_json_loads
from fastapi import FastAPI, HTTPException, APIRouter, UploadFile, File, Depends, status,Form,Body
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, or_, text, select
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import os
from typing import List
import shutil
import logging
from ..model import User, Conversation
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Optional
import zipfile
import tempfile
import hashlib
import json
from pathlib import Path
from core.app.database import get_db
# 导入模型和AI系统
from ..model import User
from .ai import CodeAnalysisChatSystem
from ..database import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
# 初始化AI系统
ai_system = CodeAnalysisChatSystem(api_key="sk-a44ec9c560504eb7a151b3ea9c5794e9")
ANALYSIS_TIMEOUT = 1200

# 数据库模型定义
Base = declarative_base()
DATABASE_URL = "mysql+pymysql://root:123456@localhost/biyesheji"

# 分析请求和响应模型
class AnalysisRequest(BaseModel):
    file_id: int
    analysis_type: str

class AnalysisResult(BaseModel):
    analysis_id: int
    file_id: int
    analysis_type: str
    summary: str
    details: dict
    created_at: str

    class Config:
        orm_mode = True

class IssueBase(BaseModel):
    issue_id: int
    analysis_id: int
    file_path: str
    severity: str
    category: str
    description: str
    recommendation: Optional[str]
    line_number: Optional[int]
    status: str
    created_at: str

    class Config:
        orm_mode = True
class CodeFile(Base):
    __tablename__ = "CodeFile"

    code_file_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)
    file_name = Column(String(255))
    file_path = Column(String(512))
    created_at = Column(String(60))

engine = create_engine(DATABASE_URL)
# 创建数据库表
Base.metadata.create_all(bind=engine)



# Pydantic模型
class FileBase(BaseModel):
    code_file_id: int
    user_id: int
    file_name: str
    file_path: str
    created_at: str

    class Config:
        orm_mode = True


# 文件存储配置
UPLOAD_FOLDER = "D:\\biyesheji\\user_code"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

daima = APIRouter()
app = FastAPI()




# Authentication related code
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="denglu/")


def get_current_user(
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="无效凭证")

        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="用户不存在")

        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="凭证验证失败")


def _extract_issues_from_analysis(analysis_results: Dict) -> List[Dict]:
    """从AI分析结果中提取问题"""
    issues = []
    for file_path, analysis in analysis_results.items():
        if isinstance(analysis, str):
            # 解析AI返回的文本分析结果
            if "潜在问题" in analysis:
                problem_section = analysis.split("潜在问题")[1]
                if "改进建议" in problem_section:
                    problem_section = problem_section.split("改进建议")[0]

                problems = [
                    line.strip()
                    for line in problem_section.split("\n")
                    if line.strip() and not line.startswith("---")
                ]

                for problem in problems:
                    issues.append({
                        "file": file_path,
                        "description": problem,
                        "severity": "high" if "高危" in problem else "medium",
                        "category": "general"
                    })

    return issues


def _extract_metrics_from_analysis(analysis_results: Dict) -> Dict:
    """从AI分析结果中提取度量指标"""
    metrics = {
        "files_analyzed": len(analysis_results),
        "total_issues": 0,
        "issue_distribution": {}
    }

    for file_path, analysis in analysis_results.items():
        if isinstance(analysis, str):
            # 简单统计问题数量
            issue_count = analysis.lower().count("问题")
            metrics["total_issues"] += issue_count
            metrics["issue_distribution"][file_path] = issue_count

    return metrics
# 代码分析API
@daima.post("/analyze", response_model=AnalysisResult)
async def analyze_code(
        request: AnalysisRequest,
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)
):
    """执行代码分析（使用AI系统的主要分析方式）"""
    try:
        # 1. 检查是否已有分析结果
        existing_analysis = await asyncio.to_thread(
            db.execute,
            text("""
                SELECT ca.* FROM code_analysis ca
                JOIN codefile cf ON ca.code_file_id = cf.code_file_id
                WHERE ca.code_file_id = :file_id 
                AND cf.user_id = :user_id
                ORDER BY ca.created_at DESC
                LIMIT 1
            """),
            {"file_id": request.file_id, "user_id": current_user.user_id}
        )

        # 如果有最近的分析结果且不超过1小时，直接返回
        # if existing_analysis:
            # last_analysis_time = datetime.strptime(existing_analysis['created_at'], "%Y-%m-%d %H:%M:%S")
            # if (datetime.now() - last_analysis_time).total_seconds() < 3600:  # 1小时内不重复分析
            #     return {
            #         "analysis_id": existing_analysis['analysis_id'],
            #         "file_id": request.file_id,
            #         "analysis_type": existing_analysis['analysis_type'],
            #         "summary": existing_analysis['summary'],
            #         "details": json.loads(existing_analysis['raw_results']),
            #         "created_at": existing_analysis['created_at']
            #     } # 1小时内不重复分析
        # 1. 验证文件存在性
        db_file = await asyncio.to_thread(
            db.execute,
            text("""
                SELECT file_path FROM codefile 
                WHERE code_file_id = :code_file_id 
                AND user_id = :user_id
            """),
            {"code_file_id": request.file_id, "user_id": current_user.user_id}
        )
        db_file = db_file.mappings().first()

        if not db_file:
            raise HTTPException(status_code=404, detail="文件未找到或无权访问")

        # 2. 检查物理文件
        file_path = Path(db_file['file_path'])
        if not await asyncio.to_thread(file_path.exists):
            raise HTTPException(status_code=404, detail="物理文件不存在")

        # 3. 使用AI系统进行代码分析
        try:
            # 根据文件类型选择分析方法
            if file_path.suffix.lower() == '.zip':
                analysis_results = await asyncio.to_thread(
                    ai_system.analyze_zip,
                    zip_path=str(file_path)
                )
            else:
                # 对于单个文件，模拟ZIP分析结构
                content = await asyncio.to_thread(
                    ai_system._read_file_with_fallback,
                    file_path=file_path
                )
                if not content:
                    raise HTTPException(status_code=400, detail="无法读取文件内容")

                analysis = await asyncio.to_thread(
                    ai_system._analyze_file,
                    file_path=file_path,
                    content=content
                )
                analysis_results = {
                    str(file_path.name): analysis
                }

            # 生成摘要
            summary = await asyncio.to_thread(
                ai_system.generate_summary,
                analysis_results=analysis_results
            )

            # 格式化结果
            formatted_results = {
                "summary": summary,
                "details": {
                    "files_analyzed": len(analysis_results),
                    "issues": _extract_issues_from_analysis(analysis_results),  # 移除了self.
                    "metrics": _extract_metrics_from_analysis(analysis_results)  # 移除了self.
                }
            }

        except Exception as ai_error:
            logger.error(f"AI分析失败: {str(ai_error)}")
            raise HTTPException(status_code=500, detail=f"AI分析失败: {str(ai_error)}")

        # 4. 保存分析结果
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            result = await asyncio.to_thread(
                db.execute,
                text("""
                    INSERT INTO code_analysis 
                    (code_file_id, analysis_type, summary, raw_results, created_at)
                    VALUES 
                    (:code_file_id, :analysis_type, :summary, :raw_results, :created_at)
                """),
                {
                    "code_file_id": request.file_id,
                    "analysis_type": request.analysis_type,
                    "summary": formatted_results.get("summary", "分析完成"),
                    "raw_results": json.dumps(formatted_results.get("details", {})),
                    "created_at": now
                }
            )
            db.commit()
            analysis_id = result.lastrowid

            # 保存分析问题
            if "issues" in formatted_results.get("details", {}):
                issue_values = []
                for issue in formatted_results["details"]["issues"]:
                    issue_values.append({
                        "analysis_id": analysis_id,
                        "file_path": issue.get("file", ""),
                        "severity": issue.get("severity", "medium"),
                        "category": issue.get("category", request.analysis_type),
                        "description": issue.get("description", ""),
                        "recommendation": issue.get("recommendation", ""),
                        "line_number": issue.get("line_number"),
                        "status": "open",
                        "created_at": now
                    })

                if issue_values:
                    await asyncio.to_thread(
                        db.execute,
                        text("""
                            INSERT INTO analysis_issue 
                            (analysis_id, file_path, severity, category, description, 
                             recommendation, line_number, status, created_at)
                            VALUES 
                            (:analysis_id, :file_path, :severity, :category, 
                             :description, :recommendation, :line_number, :status, :created_at)
                        """),
                        issue_values
                    )
                    db.commit()

            return {
                "analysis_id": analysis_id,
                "file_id": request.file_id,
                "analysis_type": request.analysis_type,
                "summary": formatted_results.get("summary", "分析完成"),
                "details": formatted_results.get("details", {}),
                "created_at": now
            }

        except Exception as db_error:
            db.rollback()
            logger.error(f"数据库保存失败: {str(db_error)}")
            raise HTTPException(status_code=500, detail="分析结果保存失败")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"分析流程异常: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"分析过程中出错: {str(e)}")


# 新增的请求响应模型
class ChatRequest(BaseModel):
    message: str
    use_context: bool = True
    conversation_id: Optional[int] = None
    file_path: Optional[str] = None  # 新增：关联代码文件路径
    zip_path: Optional[str] = None  # 新增：关联ZIP文件路径
    code_file_id: Optional[int] = None  # 数据库中的文件ID
    # @validator('code_file_id')
    # def validate_code_file_id(cls, v, values):
    #     if 'conversation_id' not in values or values['conversation_id'] is None:
    #         if v is None:
    #             raise ValueError("创建新对话时需要提供 code_file_id")
    #     return v


class ChatResponse(BaseModel):
    """
    聊天响应模型
    """
    message: str = Field(..., description="AI返回的消息内容")
    status: str = Field("success", description="请求状态")
    timestamp: datetime = Field(default_factory=datetime.now, description="响应时间戳")
    conversation_id: Optional[int] = Field(None, description="关联的会话ID")
    response: Optional[str] = Field(None, description="兼容旧版的响应字段")

    # 添加配置以兼容旧字段名
    class Config:
        extra = "allow"  # 允许额外字段
        json_encoders = {
            datetime: lambda v: v.strftime("%Y-%m-%d %H:%M:%S")
        }

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 新增的对话相关模型
class ConversationMessageResponse(BaseModel):
    # message_id: int
    conversation_id: int
    role: str
    content: str
    created_at: str
    is_active: bool
    code_file_id:int
    user_id:int

    class Config:
        orm_mode = True

# 获取对话消息历史
# @daima.get("/conversation/{conversation_id}/messages", response_model=List[ConversationMessageResponse])
# async def get_conversation_messages(
#         conversation_id: int,
#         current_user: User = Depends(get_current_user),
#         db: Session = Depends(get_db)
# ):
#     """获取特定对话的消息历史"""
#     # 验证对话所有权
#     conversation = db.execute(
#         text("""
#             SELECT 1 FROM conversation
#             WHERE conversation_id = :conversation_id
#             AND user_id = :user_id
#         """),
#         {"conversation_id": conversation_id, "user_id": current_user.user_id}
#     ).fetchone()
#
#     if not conversation:
#         raise HTTPException(status_code=404, detail="对话不存在或无权访问")
#
#     # 获取消息历史
#     messages = db.execute(
#         text("""
#             SELECT * FROM conversation_message
#             WHERE conversation_id = :conversation_id
#             ORDER BY timestamp ASC
#         """),
#         {"conversation_id": conversation_id}
#     ).mappings().fetchall()
#
#     return [
#         {
#             "message_id": m["message_id"],
#             "conversation_id": m["conversation_id"],
#             "role": m["role"],
#             "content": m["content"],
#             "timestamp": m["timestamp"]
#         }
#         for m in messages
#     ]
class ConversationResponse(BaseModel):
    conversation_id: int
    code_file_id: int
    file_name: str
    is_active: bool
    created_at: str
    last_message: Optional[str]
    last_message_time: Optional[str]

    class Config:
        orm_mode = True

# 获取用户会话列表
@daima.get("/conversations", response_model=List[ConversationResponse])
async def get_user_conversations(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """获取用户的所有对话列表"""
    # 获取对话基本信息
    conversations = db.execute(
        text("""
            SELECT 
                c.conversation_id, 
                c.code_file_id, 
                cf.file_name,
                c.is_active, 
                c.created_at
            FROM conversation c
            JOIN codefile cf ON c.code_file_id = cf.code_file_id
            WHERE c.user_id = :user_id
            ORDER BY c.created_at DESC
        """),
        {"user_id": current_user.user_id}
    ).mappings().fetchall()

    # 获取每个对话的最后一条消息
    enhanced_conversations = []
    for conv in conversations:
        last_message = db.execute(
            text("""
                SELECT content, timestamp 
                FROM conversation_message 
                WHERE conversation_id = :conversation_id
                ORDER BY timestamp DESC
                LIMIT 1
            """),
            {"conversation_id": conv["conversation_id"]}
        ).fetchone()

        enhanced_conversations.append({
            "conversation_id": conv["conversation_id"],
            "code_file_id": conv["code_file_id"],
            "file_name": conv["file_name"],
            "is_active": conv["is_active"],
            "created_at": conv["created_at"],
            "last_message": last_message[0] if last_message else None,
            "last_message_time": last_message[1] if last_message else None
        })
    print(enhanced_conversations)
    return enhanced_conversations

# 修改后的chat端点
# @daima.post("/chat", response_model=ChatResponse)
# async def chat_with_ai(
#         request: ChatRequest = Body(...),
#         current_user: User = Depends(get_current_user),
#         db: Session = Depends(get_db)
# ):
#     """与AI系统进行对话"""
#     try:
#         # 1. 验证对话ID有效性（如果提供了对话ID）
#         conversation = None
#         if request.conversation_id:
#             conversation = db.execute(
#                 text("""
#                     SELECT * FROM conversation
#                     WHERE conversation_id = :conversation_id
#                     AND user_id = :user_id
#                 """),
#                 {"conversation_id": request.conversation_id, "user_id": current_user.user_id}
#             ).fetchone()
#
#         # 2. 如果没有提供对话ID，创建一个新对话
#         if not conversation:
#             if request.code_file_id is None:
#                 raise HTTPException(status_code=400, detail="创建新对话需要关联代码文件")
#
#             code_file = db.execute(
#                 text("""
#                     SELECT file_path FROM codefile
#                     WHERE code_file_id = :code_file_id
#                     AND user_id = :user_id
#                 """),
#                 {"code_file_id": request.code_file_id, "user_id": current_user.user_id}
#             ).fetchone()
#
#             if not code_file:
#                 raise HTTPException(status_code=404, detail="代码文件不存在或无权访问")
#
#             result = db.execute(
#                 text("""
#                     INSERT INTO conversation
#                     (user_id, code_file_id, is_active, role,created_at,content)
#                     VALUES
#                     (:user_id, :code_file_id, :is_active, :role, :created_at, :content)
#                 """),
#                 {
#                     "user_id": current_user.user_id,
#                     "code_file_id": request.code_file_id,
#                     "is_active": True,
#                     "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#                     "role": "assistant",
#                     "content":"你好，有什么需要询问的？"
#                 }
#             )
#             db.commit()
#             conversation_id = result.lastrowid
#         else:
#             conversation_id = request.conversation_id
#
#         # 3. 保存用户消息到数据库
#         db.execute(
#             text("""
#                 INSERT INTO conversation
#                 (user_id, code_file_id, is_active, role,created_at,content)
#                 VALUES
#                 (:user_id, :code_file_id, :is_active, :role, :created_at, :content)
#             """),
#             {
#                 "user_id": current_user.user_id,
#                 "code_file_id": request.code_file_id,
#                 "is_active": True,
#                 "role": "user",
#                 "content": request.message,
#                 "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#             }
#         )
#         db.commit()
#
#         # 4. 准备调用AI系统的参数
#         chat_kwargs = {
#             "message": request.message,
#             "use_code_context": request.use_context,
#             "zip_path": request.zip_path if hasattr(request, 'zip_path') else None
#         }
#         if request.file_path:
#             chat_kwargs["file_path"] = request.file_path
#
#         # 5. 如果使用上下文，获取相关代码文件内容
#         if request.use_context and request.code_file_id:
#             code_file = db.execute(
#                 text("SELECT file_path FROM codefile WHERE code_file_id = :file_id"),
#                 {"file_id": request.code_file_id}
#             ).fetchone()
#
#             if code_file and code_file[0]:
#                 chat_kwargs["file_path"] = code_file[0]
#
#         # 6. 调用AI系统获取响应
#         response = ai_system.chat(**chat_kwargs)
#
#         # 7. 保存AI响应到数据库
#         db.execute(
#             text("""
#                 INSERT INTO conversation
#                 (user_id, code_file_id, is_active, role,created_at,content)
#                 VALUES
#                 (:user_id, :code_file_id, :is_active, :role, :created_at, :content)
#             """),
#             {
#                 "user_id": current_user.user_id,
#                 "code_file_id": request.code_file_id,
#                 "is_active": True,
#                 "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#                 "role": "assistant",
#                 "content": response
#             }
#         )
#         db.commit()
#
#         # return {
#         #     "response": response,
#         #     "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#         #     "conversation_id": conversation_id
#         # }
#         response_data = {
#             "message": response,  # AI返回的消息
#             "status": "success",
#             "conversation_id": request.conversation_id if hasattr(request, 'conversation_id') else None,
#             # 兼容旧字段
#             "response": response
#         }
#
#         return ChatResponse(**response_data)
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Chat error: {str(e)}", exc_info=True)
#         db.rollback()
#         raise HTTPException(
#             status_code=500,
#             detail=f"对话过程中出错: {str(e)}"
#         )
@daima.post("/chat", response_model=ChatResponse)
async def chat_with_ai(
        request: ChatRequest = Body(...),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """与AI系统进行对话（增强代码上下文版本）"""
    try:
        # 1. 验证对话ID有效性（如果提供了对话ID）
        conversation = None
        if request.conversation_id:
            conversation = db.execute(
                text("""
                    SELECT * FROM conversation 
                    WHERE conversation_id = :conversation_id 
                    AND user_id = :user_id
                """),
                {"conversation_id": request.conversation_id, "user_id": current_user.user_id}
            ).fetchone()

        # 2. 如果没有提供对话ID，创建一个新对话
        if not conversation:
            if request.code_file_id is None:
                raise HTTPException(status_code=400, detail="创建新对话需要关联代码文件")

            code_file = db.execute(
                text("""
                    SELECT file_path, file_name FROM codefile 
                    WHERE code_file_id = :code_file_id 
                    AND user_id = :user_id
                """),
                {"code_file_id": request.code_file_id, "user_id": current_user.user_id}
            ).fetchone()

            if not code_file:
                raise HTTPException(status_code=404, detail="代码文件不存在或无权访问")

            # 获取文件内容用于初始上下文
            file_content = safe_read_file(code_file.file_path) if code_file.file_path else ""

            result = db.execute(
                text("""
                    INSERT INTO conversation 
                    (user_id, code_file_id, is_active, role, created_at, content)
                    VALUES 
                    (:user_id, :code_file_id, :is_active, :role, :created_at, :content)
                """),
                {
                    "user_id": current_user.user_id,
                    "code_file_id": request.code_file_id,
                    "is_active": True,
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "role": "assistant",
                    "content": f"已加载文件: {code_file.file_name}..." if file_content else "你好，有什么需要询问的？"
                }
            )
            db.commit()
            conversation_id = result.lastrowid
        else:
            conversation_id = request.conversation_id

        # 3. 保存用户消息到数据库
        db.execute(
            text("""
                INSERT INTO conversation 
                (user_id, code_file_id, is_active, role, created_at, content)
                VALUES 
                (:user_id, :code_file_id, :is_active, :role, :created_at, :content)
            """),
            {
                "user_id": current_user.user_id,
                "code_file_id": request.code_file_id,
                "is_active": True,
                "role": "user",
                "content": request.message,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
        db.commit()

        # 4. 准备调用AI系统的参数（增强代码上下文处理）
        chat_kwargs = {
            "message": request.message,
            "use_code_context": request.use_context,
        }

        # 获取关联代码文件内容（如果使用上下文）
        if request.use_context and request.code_file_id:
            code_file = db.execute(
                text("""
                    SELECT file_path, file_name FROM codefile 
                    WHERE code_file_id = :file_id AND user_id = :user_id
                """),
                {"file_id": request.code_file_id, "user_id": current_user.user_id}
            ).fetchone()

            if code_file and code_file.file_path:
                # 自动识别ZIP文件
                if code_file.file_path.endswith('.zip'):
                    chat_kwargs["zip_path"] = code_file.file_path
                else:
                    chat_kwargs["file_path"] = code_file.file_path

                # 记录分析日志
                db.execute(
                    text("""
                        INSERT INTO code_analysis 
                        (code_file_id, analysis_type, created_at)
                        VALUES 
                        (:code_file_id, 'chat_context', :created_at)
                    """),
                    {
                        "code_file_id": request.code_file_id,
                        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                )
                db.commit()

        # 5. 调用AI系统获取响应
        response = ai_system.chat(**chat_kwargs)

        # 6. 保存AI响应到数据库
        db.execute(
            text("""
                INSERT INTO conversation 
                (user_id, code_file_id, is_active, role, created_at, content)
                VALUES 
                (:user_id, :code_file_id, :is_active, :role, :created_at, :content)
            """),
            {
                "user_id": current_user.user_id,
                "code_file_id": request.code_file_id,
                "is_active": True,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "role": "assistant",
                "content": response
            }
        )
        db.commit()

        return ChatResponse(
            message=response,
            conversation_id=conversation_id,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Chat error: {str(e)}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"对话过程中出错: {str(e)}"
        )
# 获取分析历史
@daima.get("/analysis/history", response_model=List[AnalysisResult])
async def get_analysis_history(
        file_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    # 验证文件所有权
    db_file = db.execute(
        text("SELECT * FROM codefile WHERE code_file_id = :file_id AND user_id = :user_id"),
        {"file_id": file_id, "user_id": current_user.user_id}
    ).fetchone()

    if not db_file:
        raise HTTPException(status_code=404, detail="文件未找到或无权访问")

    # 获取分析历史 - 修改这里的列名
    analyses = db.execute(
        text("SELECT * FROM code_analysis WHERE code_file_id = :file_id AND analysis_type = :code_review ORDER BY created_at DESC"),
        {"file_id": file_id,"code_review": "code_review"}
    ).mappings().fetchall()
    return [
        {
            "analysis_id": a['analysis_id'],
            "file_id": a['code_file_id'],  # 这里也要修改
            "analysis_type": a['analysis_type'],
            "summary": a['summary'],
            "details": safe_json_loads(a["raw_results"]),
            "created_at": a['created_at']
        }
        for a in analyses
    ]


# 获取分析问题列表
@daima.get("/analysis/issues", response_model=List[IssueBase])
async def get_analysis_issues(
        analysis_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    # 验证分析记录所有权
    analysis = db.execute(
        text("SELECT * FROM code_analysis ca "
        "JOIN codefile cf ON ca.file_id = cf.code_file_id "
        "WHERE ca.analysis_id = :analysis_id AND cf.user_id = :user_id"),
        {"analysis_id": analysis_id, "user_id": current_user.user_id}
    ).fetchone()

    if not analysis:
        raise HTTPException(status_code=404, detail="分析记录未找到或无权访问")

    # 获取问题列表
    issues = db.execute(
        text("SELECT * FROM analysis_issue WHERE analysis_id = :analysis_id"),
        {"analysis_id": analysis_id}
    ).fetchall()

    return issues


# 辅助函数：执行代码分析
async def perform_code_analysis(file_path: str, analysis_type: str) -> dict:
    """执行代码分析，整合AI分析系统"""
    try:
        # 1. 初始化AI分析系统（实际应从配置读取）
        ai_system = CodeAnalysisChatSystem(
            api_key="sk-a44ec9c560504eb7a151b3ea9c5794e9",
            base_url="https://api.deepseek.com/v1"
        )

        # 2. 分析ZIP文件
        analysis_results = ai_system.analyze_zip(file_path)

        # 3. 根据不同类型生成报告
        if analysis_type == "security":
            return {
                "summary": "安全分析完成",
                "details": {
                    "issues": _format_security_issues(analysis_results),  # 移除了self
                    "file_count": len(analysis_results)
                }
            }
        elif analysis_type == "performance":
            return {
                "summary": "性能分析完成",
                "details": {
                    "hotspots": _find_performance_hotspots(analysis_results),  # 移除了self
                    "file_count": len(analysis_results)
                }
            }
        else:  # 全面分析
            return {
                "summary": "全面分析完成",
                "details": {
                    "overview": _generate_overview(analysis_results),  # 移除了self
                    "issues": _format_security_issues(analysis_results),
                    "hotspots": _find_performance_hotspots(analysis_results),
                    "file_count": len(analysis_results)
                }
            }

    except Exception as e:
        logger.error(f"分析失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# 辅助方法改为独立函数
def _format_security_issues(analysis_results: dict) -> list:
    """从AI分析结果提取安全问题"""
    issues = []
    for file_path, analysis in analysis_results.items():
        if isinstance(analysis, str):  # 确保analysis是字符串
            if "security" in analysis.lower() or "漏洞" in analysis.lower():
                issues.append({
                    "type": "security",
                    "severity": "high" if "高危" in analysis else "medium",
                    "file": file_path,
                    "description": analysis.split("潜在问题:")[-1].split("\n")[
                        0].strip() if "潜在问题:" in analysis else "",
                    "recommendation": analysis.split("改进建议:")[-1].strip() if "改进建议:" in analysis else ""
                })
    return issues


def _find_performance_hotspots(analysis_results: dict) -> list:
    """从AI分析结果提取性能问题"""
    hotspots = []
    for file_path, analysis in analysis_results.items():
        if isinstance(analysis, str):  # 确保analysis是字符串
            if "性能" in analysis or "优化" in analysis:
                hotspots.append({
                    "file": file_path,
                    "issue": analysis.split("潜在问题:")[-1].split("\n")[0].strip() if "潜在问题:" in analysis else "",
                    "suggestion": analysis.split("改进建议:")[-1].strip() if "改进建议:" in analysis else "",
                    "severity": "high" if "严重" in analysis else "medium"
                })
    return hotspots


def _generate_overview(analysis_results: dict) -> dict:
    """生成代码库概览"""
    tech_stack = set()
    file_types = {}

    for file_path in analysis_results.keys():
        # 识别技术栈
        if file_path.endswith(".py"):
            tech_stack.add("Python")
        elif file_path.endswith(".js"):
            tech_stack.add("JavaScript")

        # 统计文件类型
        ext = Path(file_path).suffix
        file_types[ext] = file_types.get(ext, 0) + 1

    return {
        "tech_stack": list(tech_stack),
        "file_types": file_types,
        "total_files": len(analysis_results)
    }

# 文件上传接口（修改版）
@daima.post("/upload", response_model=FileBase)
async def upload_single_zip_file(
    file: UploadFile = File(...),
    conversation_id: int = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 检查文件类型
    if not file.filename.lower().endswith('.zip'):
        raise HTTPException(400, detail="仅支持ZIP格式文件")

    # 验证对话有效性
    conv = db.query(CodeFile).filter(
        CodeFile.code_file_id == conversation_id,
        CodeFile.user_id == current_user.user_id
    ).first()
    if not conv:
        print(conversation_id,"--",current_user.user_id)
        from sqlalchemy import inspect
        inspector = inspect(db.get_bind())
        print("实际表字段:", [c['name'] for c in inspector.get_columns('codefile')])
        raise HTTPException(400, detail="无效的对话ID")

    # 直接使用原始文件名（不再添加对话ID标记）
    original_filename = file.filename
    file_path = os.path.join(UPLOAD_FOLDER, f"user_{current_user.user_id}", original_filename)

    # 精确查重（仅检查完全相同的文件名）
    existing_file = db.query(CodeFile).filter(
        CodeFile.user_id == current_user.user_id,
        CodeFile.file_name == original_filename,
        CodeFile.file_path.isnot(None)
    ).first()

    if existing_file:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "file_exists",
                "message": f"文件 {original_filename} 已存在"
            }
        )

    # 保存文件
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    # 更新数据库（使用原始文件名）
    conv.file_name = original_filename
    conv.file_path = file_path
    db.commit()
    return {
        # "user_id":
        "code_file_id": conv.code_file_id,
        "user_id": current_user.user_id,
        "file_name": conv.file_name,
        "file_path": conv.file_path,
        "created_at": conv.created_at
    }

# 获取用户文件列表
@daima.get("/", response_model=List[FileBase])
async def get_user_files(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    # 获取文件列表
    files = db.query(CodeFile).filter(CodeFile.user_id == current_user.user_id).all()
    if not files:
        return []

    # 检查每个文件是否有分析结果
    enhanced_files = []
    for file in files:
        file_dict = {
            "code_file_id": file.code_file_id,
            "user_id": file.user_id,
            "file_name": file.file_name,
            "file_path": file.file_path or "",
            "created_at": file.created_at
        }

        # 检查是否有分析记录（不修改数据库，动态计算）
        analysis = db.execute(
            text("""
                SELECT 1 FROM code_analysis 
                WHERE code_file_id = :file_id 
                LIMIT 1
            """),
            {"file_id": file.code_file_id}
        ).fetchone()

        # 添加分析状态标记（不修改数据库结构）
        file_dict["has_analysis"] = bool(analysis)

        enhanced_files.append(file_dict)

    return enhanced_files
# 下载文件
@daima.get("/download/{file_id}")
async def download_file(
        file_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    db_file = db.query(CodeFile).filter(
        CodeFile.code_file_id == file_id,
        CodeFile.user_id == current_user.user_id
    ).first()

    if not db_file:
        raise HTTPException(status_code=404, detail="文件未找到")

    if not os.path.exists(db_file.file_path):
        raise HTTPException(status_code=404, detail="文件不存在")

    from fastapi.responses import FileResponse
    return FileResponse(
        path=db_file.file_path,
        filename=db_file.file_name,
        media_type='application/octet-stream'
    )


# 删除文件
@daima.delete("/{file_id}")
async def delete_file(
        file_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    db_file = db.query(CodeFile).filter(
        CodeFile.code_file_id == file_id,
        CodeFile.user_id == current_user.user_id
    ).first()

    if not db_file:
        raise HTTPException(status_code=404, detail="文件未找到")

    try:
        # 删除物理文件
        if os.path.exists(db_file.file_path):
            os.remove(db_file.file_path)

        # 删除数据库记录
        db.delete(db_file)
        db.commit()

        return {"message": "文件删除成功"}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"文件删除失败: {str(e)}"
        )


@daima.get("/conversation/{conversation_id}/messages", response_model=List[ConversationMessageResponse])
async def get_conversation_messages(
    conversation_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 验证对话所有权
    conversation = db.execute(
        text("""
            SELECT 1 FROM conversation 
            WHERE code_file_id = :conversation_id 
            AND user_id = :user_id
        """),
        {"conversation_id": conversation_id, "user_id": current_user.user_id}
    ).fetchone()
    # if not conversation:
    #     raise HTTPException(status_code=404, detail="对话不存在或无权访问")

    # 获取消息历史
    messages = db.execute(
        text("""
            SELECT * FROM conversation
            WHERE code_file_id = :conversation_id
            AND user_id = :user_id
            ORDER BY created_at ASC
        """),
        {"conversation_id": conversation_id,"user_id": current_user.user_id}
    ).mappings().fetchall()
    print(messages)
    return [
        {
            # "message_id": m["message_id"],
            "conversation_id": m["conversation_id"],
            "code_file_id":m["code_file_id"],
            "role": m["role"],
            "content": m["content"],
            "created_at": m["created_at"],
            "is_active":True,
            "user_id":current_user.user_id,

        }
        for m in messages
    ]