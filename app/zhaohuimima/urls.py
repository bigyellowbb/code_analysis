from fastapi import FastAPI, HTTPException, APIRouter
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime

mima = APIRouter()
app = FastAPI()
# 数据库连接URL
DATABASE_URL = "mysql+pymysql://root:123456@localhost/biyesheji"

# 创建数据库引擎
engine = create_engine(DATABASE_URL)

# 创建SessionLocal类，用于数据库会话
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 创建Base类，用于定义数据库模型
Base = declarative_base()
# 定义忘记密码的请求体模型
class ForgotPasswordRequest(BaseModel):
    phone: str
    email: str

class User(Base):
    __tablename__ = "user"
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(60), unique=True, index=True)
    password = Column(String(60))
    email = Column(String(60), unique=True, index=True)
    created_at = Column(String(60))
    phone = Column(String(60), unique=True, index=True)

@mima.post("/ForgotPassword/")
def forgot_password(request: ForgotPasswordRequest):
    db = SessionLocal()

    # 查询用户是否存在
    user = db.query(User).filter(
        User.phone == request.phone,
        User.email == request.email
    ).first()
    if not user:
        db.close()
        raise HTTPException(status_code=400, detail="手机号或邮箱不匹配")
    db.close()
    return {
        "message": "密码找回成功",
        "password": user.password  # 返回用户的密码
    }