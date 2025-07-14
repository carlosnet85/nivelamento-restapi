from datetime import datetime, timedelta, timezone
from sqlite3 import IntegrityError
from typing import Annotated, Dict, Optional, List
from starlette import status
from jose import JWTError, jwt
from passlib.context import CryptContext    
from typing import List
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import APIRouter, Depends, FastAPI, HTTPException
from sqlalchemy import DateTime, Float, ForeignKey, create_engine, Column, Integer, String, func
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
from pydantic import BaseModel, EmailStr, constr

SQLALCHEMY_DATABASE_URL = "postgresql://carlos:85135867@localhost:5432/customers"
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")
Base = declarative_base()
app = FastAPI()

class Token(BaseModel):
    access_token: str
    token_type: str

class Subscription(Base):
    __tablename__ = "subscriptions"
    
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    customer_id = Column(Integer, ForeignKey("customers.id"))
    price = Column(Float)
    installments = Column(Integer)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    customer = relationship("Customer", back_populates="subscriptions")

class SubscriptionBase(BaseModel):
    name: str
    price: float
    installments: int

class SubscriptionCreate(SubscriptionBase):
    pass

class SubscriptionIn(SubscriptionBase):
    id: int
    customer_id: int
    created_at: datetime

    class Config:
        from_attributes = True

class SubscriptionUpdate(BaseModel):
    name: Optional[str] = None
    price: Optional[float] = None
    installments: Optional[int] = None

class Customer(Base):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class CustomersBase(BaseModel):
    name: str
    email: EmailStr

class CustomerCreate(CustomersBase):
    password: constr(min_length=8) # type: ignore

class CustomerUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None


class CustomerIn(CustomersBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class CustomerOut(BaseModel):
    id: int
    name: str
    email: EmailStr
    created_at: datetime
    updated_at: Optional[datetime] = None
    subscriptions: List[SubscriptionIn]
    total_subscriptions: int
    total_monthly_price: float

    class Config:
        from_attributes = True

Customer.subscriptions = relationship("Subscription", back_populates="customer")

Base.metadata.create_all(bind=engine)

subscriptions_router = APIRouter(prefix='/subscriptions', tags=['subscriptions'])
auth_router = APIRouter(prefix='/auth', tags=['auth'])
customers_router = APIRouter(prefix='/customers', tags=['customers'])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def authenticate_user(name: str, password: str, db: Session):
    user = db.query(Customer).filter(Customer.name == name).first()
    if not user or not bcrypt_context.verify(password, str(user.password)):
        return False
    return user

def create_access_token(email: str, user_id: int, expires_delta: timedelta):
    to_encode = {"sub": email, "id": user_id, "type": "access"}
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        user_id: int | None = payload.get("id")
        
        if username is None or user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {"username": username, "id": user_id}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[Dict[str, any], Depends(get_current_user)]

def get_all_customers(user: user_dependency, db: Session):
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    return db.query(Customer).all()

def get_customer_by_id(user: user_dependency, db: Session, customer_id: int):
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    return db.query(Customer).filter(Customer.id == customer_id).first()

def get_current_customer_info(user: user_dependency, db: db_dependency):
    db_customer = db.query(Customer).filter(Customer.id == user["id"]).first()

    if not db_customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    subscriptions = db_customer.subscriptions
    total_subscriptions = len(subscriptions)
    total_monthly_price = sum(s.price for s in subscriptions)

    return {
        "id": db_customer.id,
        "name": db_customer.name,
        "email": db_customer.email,
        "created_at": db_customer.created_at,
        "updated_at": db_customer.updated_at,
        "subscriptions": subscriptions,
        "total_subscriptions": total_subscriptions,
        "total_monthly_price": total_monthly_price,
    }

def create_customer(db: Session, customer: CustomerCreate):
    password = bcrypt_context.hash(customer.password)
    db_customer = Customer(
        name=customer.name,
        email=customer.email,
        password=password
    )
    db.add(db_customer)
    try:
        db.commit()
        db.refresh(db_customer)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Nome ou email já estão em uso.")
    return db_customer


def update_customer(user: user_dependency, db: Session, customer_id: int, customer_data: CustomerUpdate):
    if user is None:
        raise HTTPException(status_code=403, detail="Not authenticated")

    if user["id"] != customer_id:
        raise HTTPException(status_code=403, detail="You can only update your own customer")

    db_customer = db.query(Customer).filter(Customer.id == customer_id).first()
    if not db_customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    update_data = customer_data.model_dump(exclude_unset=True)
    
    if "password" in update_data:
        new_password = update_data.pop("password")
        if new_password:
            db_customer.password = bcrypt_context.hash(new_password) # type: ignore
    
    for key, value in update_data.items():
        setattr(db_customer, key, value)

    db.commit()
    db.refresh(db_customer)
    return db_customer


def delete_customer(user: user_dependency, db: Session, customer_id: int):
    if user is None:
        raise HTTPException(status_code=403, detail="Not authenticated")

    if user["id"] != customer_id:
        raise HTTPException(status_code=403, detail="You can only update your own customer")
    
    db_customer = get_customer_by_id(user, db, customer_id)
    if not db_customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    db.delete(db_customer)
    db.commit()
    return db_customer

def create_subscriptions(subscriptions: List[SubscriptionCreate], db: db_dependency, user: user_dependency):
    db_subscriptions = []

    if user is None:
        raise HTTPException(status_code=403, detail="Not authenticated")
    if not subscriptions:
        raise HTTPException(status_code=400, detail="No subscriptions provided")
    if not isinstance(subscriptions, list):
        raise HTTPException(status_code=400, detail="Subscriptions must be a list")
    
    for sub in subscriptions:
        new_subscription = Subscription(
            name=sub.name,
            customer_id=user["id"],
            price=sub.price,
            installments=sub.installments
        )
        db.add(new_subscription)
        db_subscriptions.append(new_subscription)
    
    db.commit()
    for sub in db_subscriptions:
        db.refresh(sub)
    return db_subscriptions

def delete_subscription(subscription_id: int, db: db_dependency, user: user_dependency):
    subscription = db.query(Subscription).filter(Subscription.id == subscription_id).first()

    if user is None:
        raise HTTPException(status_code=403, detail="Not authenticated")

    if not subscription:
        raise HTTPException(status_code=400, detail="No subscription provided")
    if not subscription or subscription.customer_id != user["id"]: # type: ignore
        raise HTTPException(status_code=403, detail="You can only delete your own subscriptions")
    
    db.delete(subscription)
    db.commit()
    return subscription

def update_subscription(subscription_id: int, subscription: SubscriptionUpdate, db: db_dependency, user: user_dependency):
    subscriptions = db.query(Subscription).filter(Subscription.id == subscription_id).first()

    if user is None:
        raise HTTPException(status_code=403, detail="Not authenticated")

    if not subscriptions:
        raise HTTPException(status_code=400, detail="No subscriptions provided")
    if not subscriptions or subscriptions.customer_id != user["id"]: # type: ignore
        raise HTTPException(status_code=403, detail="You can only delete your own subscriptions")
    
    update_data = subscription.model_dump(exclude_unset=True)
    
    for key, value in update_data.items():
        setattr(subscriptions, key, value)
    db.commit()
    db.refresh(subscriptions)
    return subscriptions

def list_user_subscriptions(db: db_dependency, user: user_dependency):
    if user is None:
        raise HTTPException(status_code=403, detail="Not authenticated")

    return db.query(Subscription).filter(Subscription.customer_id == user["id"]).all()

@subscriptions_router.post("/", response_model=List[SubscriptionIn], status_code=status.HTTP_201_CREATED)
def create_subscription_handler(subscriptions: List[SubscriptionCreate], db: db_dependency, user: user_dependency):
    return create_subscriptions(subscriptions, db, user)

@subscriptions_router.get("/", response_model=List[SubscriptionIn])
def list_user_subscriptions_handler(db: db_dependency, user: user_dependency):
    return list_user_subscriptions(db, user)

@subscriptions_router.delete("/{subscription_id}", response_model=SubscriptionIn)
def delete_subscription_handler(subscription_id: int, db: db_dependency, user: user_dependency):
    return delete_subscription(subscription_id, db, user)

@subscriptions_router.put("/{subscription_id}", response_model=SubscriptionIn)
def update_subscription_handler(subscription_id: int, subscription: SubscriptionUpdate, db: db_dependency, user: user_dependency):
    return update_subscription(subscription_id, subscription, db, user)

@customers_router.post("/", response_model=CustomerIn, status_code=status.HTTP_201_CREATED)
def create_customer_handler(customer: CustomerCreate, db: db_dependency):
    return create_customer(db, customer)

@customers_router.put("/{customer_id}", response_model=CustomerIn)
def update_customer_handler(user: user_dependency, customer_id: int, customer: CustomerUpdate, db: db_dependency):
    return update_customer(user, db, customer_id, customer)

@customers_router.delete("/{customer_id}", response_model=CustomerIn)
def delete_customer_handler(user: user_dependency, customer_id: int, db: db_dependency):
    return delete_customer(user, db, customer_id)

@customers_router.get("/", response_model=CustomerOut)
def get_current_customer_info_handler(user: user_dependency, db: db_dependency):
    return get_current_customer_info(user, db)

@auth_router.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = create_access_token(
        email=str(user.email), user_id=user.id, expires_delta=timedelta(minutes=10) # type: ignore
    )
    return {"access_token": token, "token_type": "bearer"}

app.include_router(auth_router)
app.include_router(customers_router)
app.include_router(subscriptions_router)