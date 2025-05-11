from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from fastapi import FastAPI, HTTPException, Depends, APIRouter, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
Base = declarative_base()

class User(Base):
    __tablename__ = "user"
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(60), unique=True, index=True)
    password = Column(String(60))
    email = Column(String(60), unique=True, index=True)
    created_at = Column(String(60))
    phone = Column(String(60))
user = APIRouter()
# 创建FastAPI应用
app = FastAPI()
# 数据库连接URL
DATABASE_URL = "mysql+pymysql://root:123456@localhost/biyesheji"

# 创建数据库引擎
engine = create_engine(DATABASE_URL)

# 创建SessionLocal类，用于数据库会话
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 定义登录请求体模型
class LoginRequest(BaseModel):
    username: str
    password: str

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 允许的前端地址
    allow_credentials=True,
    allow_methods=["*"],  # 允许所有 HTTP 方法
    allow_headers=["*"],  # 允许所有 HTTP 头
)

# 密钥和算法
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 240

# 密码哈希上下文
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 生成JWT
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=240)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 登录接口
@user.post("/denglu/")
def login(login_data: LoginRequest):
    db = SessionLocal()
    # 查询用户
    user = db.query(User).filter(User.username == login_data.username).first()

    if not user:
        raise HTTPException(status_code=400, detail="用户名不存在")

    # 验证密码
    if user.password != login_data.password:
        raise HTTPException(status_code=400, detail="密码错误")

    # 生成JWT
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {"message": "登录成功", "user_id": user.user_id, "user_name": user.username, "access_token": access_token, "token_type": "bearer"}


# 定义OAuth2方案
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="denglu/")

# 验证Token
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user
@user.get("/protected")
def protected_route(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello, {current_user.username}! This is a protected route."}
