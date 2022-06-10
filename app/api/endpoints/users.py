from typing import Any, List
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from fastapi import Depends,HTTPException, status,Request,APIRouter,Path
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from app.api import deps
from app.core.security import create_access_token

from app.crud import user
from app.schemas.token import Token
from app import schemas

router = APIRouter()

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@router.post("/login",response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(),db: Session = Depends(deps.get_db)):
    user_data=user.authenticate_user(db,form_data.username, form_data.password)
    
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token =create_access_token(
        data={"sub": user_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

    
@router.post("/", response_model=schemas.User, status_code=201)
def create_user(payload: schemas.UserCreate,db: Session = Depends(deps.get_db)):   
    db_user = user.get_user_by_email(db, email=payload.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return user.post(db,payload)    
    
    
@router.get("/{id}/", response_model=schemas.User)
def read_user(id: int = Path(..., gt=0),db: Session = Depends(deps.get_db)):
    user_data = user.get(db,id)
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")
    return user_data

@router.get("/", response_model=List[schemas.User])
def read_all_users(skip: int = 0, limit: int = 100, db: Session = Depends(deps.get_db)):
    return user.get_all(db, skip=skip, limit=limit)

@router.put("/{id}/", response_model=schemas.User)
def update_user(payload:schemas.UserUpdate,id:int=Path(...,gt=0),db: Session = Depends(deps.get_db)):
    user_data = user.get(db,id)
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")   
    return user.put(db,id,payload)

#DELETE route
@router.delete("/{id}/", response_model=schemas.User)
def delete_user(id:int = Path(...,gt=0),db: Session = Depends(deps.get_db)):
    user_data = user.get(db,id)
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")       
    return user.delete(db,id) 
