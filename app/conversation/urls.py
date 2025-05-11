from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends,File, UploadFile,Form
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List
from ..model import CodeFile, User
from ..database import get_db
from ..daimafenxi.urls import get_current_user
import os
import shutil

conversations = APIRouter()

class ConversationResponse(BaseModel):
    code_file_id: int
    file_name: str
    created_at: str
    file_path: str
    is_active_conversation: bool


# 创建新对话
@conversations.post("/new")
async def create_conversation(
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """创建新对话（初始没有关联文件）"""
    conv = CodeFile(
        user_id=current_user.user_id,
        file_name="新对话",  # 默认名称
        file_path=None,  # 对话记录没有文件路径
        is_active_conversation=False,
        created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    db.add(conv)
    db.commit()
    return {"code_file_id": conv.code_file_id, "file_name": conv.file_name}


# 获取所有对话列表（左侧任务栏）
@conversations.get("/")
async def get_conversations(
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """获取用户的所有对话记录"""

    return db.query(CodeFile).filter(
        CodeFile.user_id == current_user.user_id,
        # CodeFile.is_active_conversation == True  # 只查询对话记录
    ).order_by(CodeFile.created_at.desc()).all()


# 获取对话关联的文件（右侧文件显示）
@conversations.get("/{code_file_id}/file")
async def get_conversation_file(
        code_file_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """获取对话关联的ZIP文件（每个对话只能关联一个文件）"""
    # 1. 首先验证对话存在
    conv = db.query(CodeFile).filter(
        CodeFile.code_file_id == code_file_id,
        CodeFile.user_id == current_user.user_id,
    ).first()

    if not conv:
        raise HTTPException(status_code=404, detail="对话不存在")

        # 2. 直接查询文件名（假设CodeFile表中有file_name字段）
    file_record = db.query(CodeFile.file_name).filter(
        CodeFile.code_file_id == code_file_id,
        CodeFile.user_id == current_user.user_id
    ).first()

    if not file_record or not file_record.file_name:
        return {"message": "该对话未关联文件"}
    return {
        "code_file_id": code_file_id,
        "file_name": file_record.file_name,
        "created_at": conv.created_at,
        "file_path":conv.file_path
    }


# 上传文件并关联到对话
@conversations.post("/upload")
async def upload_file(
        file: UploadFile = File(...),
        conversation_id: int = Form(...),  # 必须关联到某个对话
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """上传ZIP文件并关联到指定对话"""
    # 1. 验证对话存在
    conv = db.query(CodeFile).filter(
        CodeFile.code_file_id == conversation_id,
        CodeFile.user_id == current_user.user_id,
        CodeFile.is_active_conversation == True
    ).first()

    if not conv:
        raise HTTPException(status_code=404, detail="对话不存在")

    # 2. 检查是否已存在关联文件
    existing_file = db.query(CodeFile).filter(
        CodeFile.user_id == current_user.user_id,
        CodeFile.file_name.like(f"%{conversation_id}%")
    ).first()

    if existing_file:
        raise HTTPException(status_code=400, detail="每个对话只能关联一个ZIP文件")

    # 3. 保存文件
    file_path = f"uploads/{current_user.user_id}/{conversation_id}_{file.filename}"
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # 4. 创建文件记录
    new_file = CodeFile(
        user_id=current_user.user_id,
        file_name=f"[对话#{conversation_id}]{file.filename}",  # 文件名包含对话ID
        file_path=file_path,
        is_active_conversation=False,
        created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    db.add(new_file)
    db.commit()

    return {
        "code_file_id": new_file.code_file_id,
        "file_name": new_file.file_name
    }
    @conversations.patch("/{conversation_id}/attach")
    async def attach_file_to_conversation(
            conversation_id: int,
            file_id: int,
            db: Session = Depends(get_db),
            current_user: User = Depends(get_current_user)
    ):
        """
        为对话关联文件
        """
        # 验证对话和文件
        conv = db.query(CodeFile).filter(
            CodeFile.code_file_id == conversation_id,
            CodeFile.user_id == current_user.user_id
        ).first()

        file = db.query(CodeFile).filter(
            CodeFile.code_file_id == file_id,
            CodeFile.user_id == current_user.user_id
        ).first()

        if not conv or not file:
            raise HTTPException(status_code=404, detail="对话或文件不存在")

        # 更新对话关联
        conv.file_path = file.file_path
        conv.file_name = f"分析 {file.file_name}"
        db.commit()

        return {"message": "文件关联成功"}