from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import List
import pandas as pd
import pickle

# Constants
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Initialize FastAPI
app = FastAPI()

# Fake database for users
fake_users_db = {
    "user@example.com": {
        "username": "user@example.com",
        "full_name": "User Example",
        "hashed_password": "fakehashedsecret",
        "disabled": False,
    }
}

# Pydantic models
class User(BaseModel):
    username: str
    email: str
    full_name: str
    disabled: bool = None

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Load ML model
with open("model.pkl", "rb") as file:
    model = pickle.load(file)

# JWT helper functions
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        exp = datetime.utcnow() + expires_delta
    else:
        exp = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": exp})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    return token_data

# Auth endpoints
@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user['hashed_password']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['username']}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# DDoS detection endpoint
@app.post("/detect")
async def detect_ddos(data: List[float], token: str = Depends(oauth2_scheme)):
    token_data = verify_token(token)
    # Perform DDoS detection using the loaded model
    result = model.predict([data])
    return {"prediction": result.tolist()}

# CSV export endpoint
@app.get("/export-data")
async def export_data(token: str = Depends(oauth2_scheme)):
    token_data = verify_token(token)
    # Example data to export
    df = pd.DataFrame({
        "timestamp": [datetime.now()],
        "event": ["example"],
        "value": [1]
    })
    csv_file = df.to_csv(index=False)
    return Response(content=csv_file, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=data.csv"})