from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from fastapi import FastAPI, HTTPException, Depends, APIRouter, Request,status
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker,Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
Base = declarative_base()
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from ..database import get_db

class User(Base):
    __tablename__ = "user"
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(60), unique=True, index=True)
    password = Column(String(60))
    email = Column(String(60), unique=True, index=True)
    created_at = Column(String(60))
    phone = Column(String(60))
me = APIRouter()
# 创建FastAPI应用
app = FastAPI()
# 数据库连接URL
DATABASE_URL = "mysql+pymysql://root:123456@localhost/biyesheji"

# 创建数据库引擎
engine = create_engine(DATABASE_URL)

# 创建SessionLocal类，用于数据库会话
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 允许的前端地址
    allow_credentials=True,
    allow_methods=["*"],  # 允许所有 HTTP 方法
    allow_headers=["*"],  # 允许所有 HTTP 头
)
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
# 密码哈希上下文
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="denglu/")


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="无效凭证")

        db = SessionLocal()
        user = db.query(User).filter(User.username == username).first()
        print("查询到的用户:", user)  # 调试
        if not user:
            raise HTTPException(status_code=404, detail="用户不存在")

        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="凭证验证失败")

@me.get("/me")
def get_current_user_info(current_user: User = Depends(get_current_user)):
    return {
        "user_id": current_user.user_id,
        "username": current_user.username,
        "email": current_user.email,
        "created_at": current_user.created_at,
        "phone": current_user.phone
    }


@me.post("/logout")
async def logout(request: Request, token: str = Depends(oauth2_scheme)):
    try:
        # 验证 token 有效性
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")

        # 在实际应用中，这里可以添加 token 到黑名单的逻辑
        # 例如使用 Redis 存储已注销的 token

        response = JSONResponse(
            content={"message": "成功退出登录"},
            status_code=status.HTTP_200_OK
        )

        return response
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的 token"
        )


class UserUpdate(BaseModel):
    email: str = None
    phone: str = None


@me.patch("/update")
async def update_user(
    update_data: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        # 从数据库重新加载用户对象
        db_user = db.query(User).filter(User.user_id == current_user.user_id).first()
        if not db_user:
            raise HTTPException(status_code=404, detail="用户不存在")

        # 只更新提供的字段
        if update_data.email is not None:
            db_user.email = update_data.email
        if update_data.phone is not None:
            db_user.phone = update_data.phone

        db.commit()
        db.refresh(db_user)

        return {
            "message": "信息更新成功",
            "user": {
                "email": db_user.email,
                "phone": db_user.phone
            }
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"更新失败: {str(e)}"
        )