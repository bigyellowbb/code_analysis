from pydantic import BaseModel
# from datetime import datetime
from typing import Optional


class UserBase(BaseModel):
    username: str
    email: str


class UserCreate(UserBase):
    password: str
    phone: Optional[str] = None


class User(UserBase):
    user_id: int
    created_at: str

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    message: str
    user_id: int
    username: str


class CodeFileBase(BaseModel):
    file_name: str


class CodeFileCreate(CodeFileBase):
    pass


class CodeFile(CodeFileBase):
    code_file_id: int
    user_id: int
    file_path: str
    file_size: int
    created_at: str

    class Config:
        from_attributes = True