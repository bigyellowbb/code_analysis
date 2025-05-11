from fastapi import FastAPI,Depends
from app.denglu.urls import user
from app.zhuce.urls import zhuce
from app.zhaohuimima.urls import mima
from app.daimafenxi.urls import daima
from app.gerenzhongxin.urls import me
from app.conversation.urls import conversations
from fastapi.security import OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="denglu/")
from sqlalchemy.ext.declarative import declarative_base

app = FastAPI()
app.include_router(user,tags=["用户登录"])
app.include_router(zhuce,tags=["用户注册"])
app.include_router(mima,tags=["找回密码"])
app.include_router(me,tags=["个人中心"])
app.include_router(daima,prefix="/files", tags=["代码分析"])
app.include_router(conversations,prefix="/conversations", tags=["对话管理"])

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080"],  # 允许的前端地址
    allow_credentials=True,
    allow_methods=["*"],  # 允许所有 HTTP 方法
    allow_headers=["*"],  # 允许所有 HTTP 头
)

@app.get("/protected")
async def protected_route(token: str = Depends(oauth2_scheme)):
    return {"message": "认证成功"}
@app.get("/")
async def home():
    return {"user":1}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)