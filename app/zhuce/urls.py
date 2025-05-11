from fastapi import FastAPI, HTTPException, APIRouter
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime

zhuce = APIRouter()
app = FastAPI()
# 数据库连接URL
DATABASE_URL = "mysql+pymysql://root:123456@localhost/biyesheji"

# 创建数据库引擎
engine = create_engine(DATABASE_URL)

# 创建SessionLocal类，用于数据库会话
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 创建Base类，用于定义数据库模型
Base = declarative_base()


# 定义用户模型
class User(Base):
    __tablename__ = "user"  # 表名
    user_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(60), unique=True, index=True)
    password = Column(String(60))
    email = Column(String(60), unique=True, index=True)
    created_at = Column(String(60), unique=True, index=True)
    phone = Column(String(60), unique=True, index=True)  # 确保手机号唯一

# 创建数据库表
# Base.metadata.create_all(bind=engine)

# 启用 CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 允许的前端地址
    allow_credentials=True,
    allow_methods=["*"],  # 允许所有 HTTP 方法，包括 OPTIONS
    allow_headers=["*"],  # 允许所有 HTTP 头
)

# 定义用户注册的请求体模型
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    phone: str  # 添加 phone 字段


# 用户注册接口
@zhuce.post("/register/")
def register_user(user: UserCreate):
    db = SessionLocal()

    # 检查用户名是否已存在
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        db.close()
        raise HTTPException(status_code=400, detail="用户名已被注册")

    # 检查手机号是否已存在
    db_phone = db.query(User).filter(User.phone == user.phone).first()
    if db_phone:
        db.close()
        raise HTTPException(status_code=400, detail="手机号码已被注册")

    # 创建新用户时，不需要提供 user_id
    new_user = User(
        username=user.username,
        email=user.email,
        password=user.password,
        phone=user.phone,
        # created_at=datetime.utcnow()
    )
    # 添加到数据库
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    db.close()

    return {"message": "注册成功", "user_id": new_user.user_id}


# # 运行应用
# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app=app, host="0.0.0.0", port=8080)