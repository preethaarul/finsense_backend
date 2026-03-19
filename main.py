from dotenv import load_dotenv
import os

load_dotenv()  
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

from fastapi import FastAPI, Depends, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
from collections import defaultdict
from datetime import datetime
from typing import Dict, Optional, List

from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

import csv
from fastapi.responses import StreamingResponse
from io import StringIO

from database import engine, SessionLocal
import models
from models import Transaction, User, Budget
from schemas import (
    TransactionCreate,
    TransactionResponse,
    UserCreate,
    UserLogin,
    Token,
    BudgetCreate,
    BudgetResponse,
    PasswordChange
)



models.Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


print("SECRET_KEY loaded:", bool(SECRET_KEY))

@app.get("/")
def root():
    return {
        "status": "success",
        "message": "FinSense FastAPI backend is running 🚀"
    }

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str):
    return pwd_context.verify(password, hashed)

def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401)
    except JWTError:
        raise HTTPException(status_code=401)

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401)

    return user

@app.post("/auth/signup", response_model=Token)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    normalized_email = user.email.strip().lower()
    
    if db.query(User).filter(
        func.lower(User.email) == normalized_email
    ).first():
        raise HTTPException(
            status_code=409, 
            detail="Email already registered"
        )
    
    new_user = User(
        name=user.name.strip(),
        email=normalized_email,  
        hashed_password=hash_password(user.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    token = create_access_token({"sub": new_user.email})
    return {
        "access_token": token, 
        "token_type": "bearer",
        "user_name": new_user.name  
    }

@app.post("/auth/login", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(
        func.lower(User.email) == user.email.lower()
    ).first()

    if not db_user:
        raise HTTPException(
            status_code=404,
            detail="ACCOUNT_NOT_FOUND"
        )

    if not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="INCORRECT_PASSWORD"
        )

    token = create_access_token({"sub": db_user.email})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user_name": db_user.name
    }


@app.post("/transactions", response_model=TransactionResponse)
def add_transaction(
    txn: TransactionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    transaction = Transaction(user_id=current_user.id, **txn.dict())
    db.add(transaction)
    db.commit()
    db.refresh(transaction)
    return transaction

@app.get("/transactions", response_model=list[TransactionResponse])
def get_transactions(
    type: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    q = db.query(Transaction).filter(Transaction.user_id == current_user.id)
    if type in ["income", "expense"]:
        q = q.filter(Transaction.type == type)

    return q.order_by(Transaction.date.desc(), Transaction.id.desc()).all()

@app.delete("/transactions/{txn_id}")
def delete_transaction(
    txn_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    txn = db.query(Transaction).filter(
        Transaction.id == txn_id,
        Transaction.user_id == current_user.id
    ).first()

    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")

    db.delete(txn)
    db.commit()
    return {"message": "Transaction deleted"}

@app.put("/transactions/{txn_id}")
def update_transaction(
    txn_id: int,
    txn: TransactionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    existing = db.query(Transaction).filter(
        Transaction.id == txn_id,
        Transaction.user_id == current_user.id
    ).first()

    if not existing:
        raise HTTPException(status_code=404, detail="Transaction not found")

    for key, value in txn.dict().items():
        setattr(existing, key, value)

    db.commit()
    return {"message": "Transaction updated"}


@app.post("/budget", response_model=BudgetResponse)
def set_budget(
    data: BudgetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    existing = db.query(Budget).filter(
        Budget.user_id == current_user.id,
        Budget.month == data.month,
        Budget.year == data.year
    ).first()

    if existing:
        existing.amount = data.amount
        db.commit()
        db.refresh(existing)
        return existing
    
    budget = Budget(
        user_id=current_user.id,
        month=data.month,
        year=data.year,
        amount=data.amount
    )
    db.add(budget)
    db.commit()
    db.refresh(budget)
    return budget

@app.get("/budget")
def get_budget(
    month: Optional[int] = Query(None),
    year: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    now = datetime.now()
    month = month or now.month
    year = year or now.year
    
    budget = db.query(Budget).filter(
        Budget.user_id == current_user.id,
        Budget.month == month,
        Budget.year == year
    ).first()
    
    if budget:
        return budget
    else:
        return {"message": "No budget set for this period", "amount": 0}

@app.get("/budget/current")
def get_current_budget(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    now = datetime.now()
    budget = db.query(Budget).filter(
        Budget.user_id == current_user.id,
        Budget.month == now.month,
        Budget.year == now.year
    ).first()
    
    if budget:
        return {
            "id": budget.id,
            "user_id": budget.user_id,
            "month": budget.month,
            "year": budget.year,
            "amount": budget.amount
        }
    else:
        return {"message": "No budget set for current month", "amount": 0}

@app.get("/budgets")
def get_all_budgets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all budgets for the current user"""
    budgets = db.query(Budget).filter(
        Budget.user_id == current_user.id
    ).order_by(
        Budget.year.desc(),
        Budget.month.desc()
    ).all()
    
    return budgets

@app.get("/dashboard/summary")
def dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    now = datetime.now()
    current_month = now.strftime("%Y-%m")
    
    expenses = db.query(Transaction).filter(
        Transaction.user_id == current_user.id,
        Transaction.type == "expense",
        Transaction.date.startswith(current_month)
    ).all()
    
    expense_this_month = sum(e.amount for e in expenses)
    expense_days = {e.date for e in expenses}
    expense_rate = round(expense_this_month / len(expense_days), 2) if expense_days else 0
    budget = db.query(Budget).filter(
        Budget.user_id == current_user.id,
        Budget.month == now.month,
        Budget.year == now.year
    ).first()
    
    monthly_budget = budget.amount if budget else 0
    remaining_balance = monthly_budget - expense_this_month
    
    category_totals = defaultdict(float)
    for e in expenses:
        category_totals[e.category] += e.amount
    
    return {
        "expense_this_month": expense_this_month,
        "expense_rate": expense_rate,
        "monthly_budget": monthly_budget,
        "remaining_balance": remaining_balance,
        "category_totals": category_totals
    }


@app.get("/dashboard/timeline")
def dashboard_timeline(
    view: str = Query("monthly"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    transactions = db.query(Transaction).filter(
        Transaction.user_id == current_user.id
    ).all()

    income = defaultdict(float)
    expense = defaultdict(float)

    for t in transactions:
        date_obj = datetime.strptime(t.date, "%Y-%m-%d")

        if view == "yearly":
            key = date_obj.strftime("%Y")
        elif view == "weekly":
            key = date_obj.strftime("%Y-%m-%d")
        else:
            key = date_obj.strftime("%Y-%m")

        if t.type == "income":
            income[key] += t.amount
        else:
            expense[key] += t.amount

    return {
        "income": dict(sorted(income.items())),
        "expense": dict(sorted(expense.items()))
    }

@app.get("/dashboard/rule-insights")
def rule_insights(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    expenses = db.query(Transaction).filter(
        Transaction.user_id == current_user.id,
        Transaction.type == "expense"
    ).all()

    if not expenses:
        return {"message": "No expense data"}

    total_spent = sum(e.amount for e in expenses)

    category_totals = defaultdict(float)
    for e in expenses:
        category_totals[e.category] += e.amount

    top_category = max(category_totals, key=category_totals.get)
    top_category_percent = round(
        (category_totals[top_category] / total_spent) * 100, 1
    )

    weekend = weekday = 0
    for e in expenses:
        if datetime.strptime(e.date, "%Y-%m-%d").weekday() >= 5:
            weekend += e.amount
        else:
            weekday += e.amount

    dominant_days = "Weekends" if weekend > weekday else "Weekdays"

    frequent_small_expenses = len([e for e in expenses if e.amount < 200]) >= 5

    return {
        "top_category": top_category,
        "top_category_percent": top_category_percent,
        "dominant_days": dominant_days,
        "frequent_small_expenses": frequent_small_expenses
    }





@app.get("/profile")
def get_profile(current_user: User = Depends(get_current_user)):
    return {
        "name": current_user.name,
        "email": current_user.email,
        "created_at": current_user.created_at.strftime("%Y-%m-%d")
    }

@app.post("/auth/change-password")
def change_password(
    data: PasswordChange,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not verify_password(data.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password incorrect")

    current_user.hashed_password = hash_password(data.new_password)
    db.commit()
    return {"message": "Password updated"}

@app.delete("/profile")
def delete_account(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    db.query(Transaction).filter(
        Transaction.user_id == current_user.id
    ).delete()

    db.query(Budget).filter(
        Budget.user_id == current_user.id
    ).delete()

    db.delete(current_user)
    db.commit()

    return {"message": "Account deleted successfully"}



@app.get("/export/transactions")
def export_transactions(
    from_month: str = Query(..., description="Start month in YYYY-MM"),
    to_month: str = Query(..., description="End month in YYYY-MM"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Export transactions within a month range as CSV
    """

    try:
        from_date = datetime.strptime(from_month, "%Y-%m")
        to_date = datetime.strptime(to_month, "%Y-%m")
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid month format. Use YYYY-MM"
        )

    if from_date > to_date:
        raise HTTPException(
            status_code=400,
            detail="from_month cannot be after to_month"
        )


    start_date = from_date.strftime("%Y-%m-01")
    end_date = (
        to_date.replace(day=28)
        .strftime("%Y-%m") + "-31"
    )

    transactions = (
        db.query(Transaction)
        .filter(
            Transaction.user_id == current_user.id,
            Transaction.date >= start_date,
            Transaction.date <= end_date
        )
        .order_by(Transaction.date.desc())
        .all()
    )

    if not transactions:
        raise HTTPException(status_code=404, detail="No transactions found")

    output = StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Date",
        "Type",
        "Category",
        "Amount",
        "Description"
    ])

    for t in transactions:
        writer.writerow([
            t.date,
            t.type.capitalize(),
            t.category,
            t.amount,
            t.description or ""
        ])

    output.seek(0)

    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                f"attachment; filename=finsense_{from_month}_to_{to_month}.csv"
            )
        }
    )





import re

@app.post("/transactions/parse-sms")
def parse_sms(payload: Dict, current_user: User = Depends(get_current_user)):
    text = payload.get("text", "")
    
    # 1. Detect Amount (₹, Rs., Rs, INR)
    amount_match = re.search(r'(?:₹|Rs\.?|INR)\s*([\d,]+(?:\.\d{2})?)', text, re.IGNORECASE)
    amount = 0.0
    if amount_match:
        amount_str = amount_match.group(1).replace(',', '')
        amount = float(amount_str)
    
    # 2. Detect Type (Debited/Spent -> Expense, Credited/Received -> Income)
    type_val = "expense" # Default
    if re.search(r'(credited|received|income|added)', text, re.IGNORECASE):
        type_val = "income"
    elif re.search(r'(debited|spent|paid|payment)', text, re.IGNORECASE):
        type_val = "expense"
        
    # 3. Detect Date (DD-MM-YY, DD-MM-YYYY, YYYY-MM-DD)
    date_val = datetime.now().strftime("%Y-%m-%d")
    date_match = re.search(r'(\d{2}[-/]\d{2}[-/]\d{2,4})|(\d{4}[-/]\d{2}[-/]\d{2})', text)
    if date_match:
        try:
            raw_date = date_match.group(0).replace('/', '-')
            # Simple normalization for common formats
            parts = raw_date.split('-')
            if len(parts[0]) == 4: # YYYY-MM-DD
                date_val = raw_date
            elif len(parts[2]) == 4: # DD-MM-YYYY
                date_val = f"{parts[2]}-{parts[1]}-{parts[0]}"
            elif len(parts[2]) == 2: # DD-MM-YY
                date_val = f"20{parts[2]}-{parts[1]}-{parts[0]}"
        except:
            pass

    # 4. Detect Category (Very basic keyword matching)
    category = "Others"
    categories = {
        "Food": ["swiggy", "zomato", "restaurant", "starbucks", "food"],
        "Shopping": ["amazon", "flipkart", "myntra", "shopping", "mall"],
        "Transport": ["uber", "ola", "petrol", "fuel", "transport"],
        "Entertainment": ["netflix", "prime", "movie", "theatre"],
        "Bills": ["electricity", "recharge", "bill", "broadband", "water"],
    }
    
    for cat, keywords in categories.items():
        if any(kw in text.lower() for kw in keywords):
            category = cat
            break

    return {
        "amount": amount,
        "type": type_val,
        "date": date_val,
        "category": category,
        "description": "Parsed from SMS"
    }

@app.get("/predictions")
def get_predictions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Fetch all past expenses
    expenses = db.query(Transaction).filter(
        Transaction.user_id == current_user.id,
        Transaction.type == "expense"
    ).all()

    if len(expenses) < 5:
        return {
            "status": "insufficient_data",
            "message": "We need at least 5 transactions to start making accurate predictions."
        }
    # Group by month
    monthly_totals = defaultdict(float)
    category_monthly = defaultdict(lambda: defaultdict(float))
    
    current_month_key = datetime.now().strftime("%Y-%m")
    
    # Get last month key for comparison
    last_month_date = datetime.now().replace(day=1)
    if last_month_date.month == 1:
        last_month_key = f"{last_month_date.year - 1}-12"
    else:
        last_month_key = f"{last_month_date.year}-{last_month_date.month - 1:02d}"

    for e in expenses:
        month_key = e.date[:7] # YYYY-MM
        monthly_totals[month_key] += e.amount
        category_monthly[e.category][month_key] += e.amount

    # Calculate overall forecast (simple average of last 3 months if available)
    sorted_months = sorted(monthly_totals.keys())
    # Exclude current incomplete month if needed, but let's keep it simple for now
    last_3_months = [m for m in sorted_months if m < current_month_key][-3:]
    if not last_3_months: last_3_months = sorted_months[-1:]
    
    avg_total = sum(monthly_totals[m] for m in last_3_months) / len(last_3_months)
    
    # Category projections
    category_projections = []
    category_suggestions = []

    for cat, months in category_monthly.items():
        # Average of this category across the same last 3 months
        cat_avg = sum(months.get(m, 0) for m in last_3_months) / len(last_3_months)
        last_month_actual = months.get(last_month_key, 0)
        
        # Trend based on comparison with last active month
        if last_month_actual > 0:
            change_pct = ((cat_avg - last_month_actual) / last_month_actual) * 100
            trend = "increasing" if cat_avg > last_month_actual else "decreasing"
        else:
            change_pct = 0
            trend = "stable"
            
        category_projections.append({
            "category": cat,
            "predicted": round(cat_avg, 2),
            "last_month": round(last_month_actual, 2),
            "change_pct": round(change_pct, 1),
            "trend": trend
        })

        if trend == "increasing" and cat_avg > (avg_total * 0.2):
            category_suggestions.append(f"Your spending in **{cat}** is projected to rise by {abs(round(change_pct, 1))}% compared to last month. Try to find alternatives!")
        elif cat_avg > (avg_total * 0.4):
            category_suggestions.append(f"**{cat}** remains your biggest cost driver. Can you cut down 10% here?")

    if not category_suggestions:
        category_suggestions.append("Your spending habits look stable! Keep tracking to maintain this financial health.")

    return {
        "status": "success",
        "forecasted_total": round(avg_total, 2),
        "last_month_total": round(monthly_totals.get(last_month_key, 0), 2),
        "category_projections": category_projections,
        "suggestions": category_suggestions
    }
