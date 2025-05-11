from fastapi import APIRouter

user = APIRouter()

@user.post("/login")
async def user_login():
    return {"user":"login"}
