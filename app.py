import os
import sqlite3
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Home route
@app.route("/")
@login_required
def index():
    """Show overview of income, expenses, and budgets"""
    user_id = session["user_id"]
    
    # Query income, expenses, and budgets
    income = db.execute("SELECT SUM(amount) AS total_income FROM income WHERE user_id = ?", user_id)[0]['total_income']
    expenses = db.execute("SELECT SUM(amount) AS total_expenses FROM expenses WHERE user_id = ?", user_id)[0]['total_expenses']
    budgets = db.execute("SELECT * FROM budgets WHERE user_id = ?", user_id)
    goals = db.execute("SELECT * FROM goals WHERE user_id = ?", user_id)

    return render_template("index.html", income=income, expenses=expenses, budgets=budgets, goals=goals)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/add_income", methods=["GET", "POST"])
@login_required
def add_income():
    """Add new income"""
    if request.method == "POST":
        user_id = session["user_id"]
        amount = request.form.get("amount")
        category = request.form.get("category")
        
        if not amount or not category:
            return apology("must provide amount and category")
        
        db.execute("INSERT INTO income (user_id, amount, category) VALUES (?, ?, ?)", user_id, amount, category)
        flash("Income added successfully!")
        return redirect("/")
    else:
        return render_template("add_income.html")

@app.route("/add_expense", methods=["GET", "POST"])
@login_required
def add_expense():
    """Add new expense"""
    if request.method == "POST":
        user_id = session["user_id"]
        amount = request.form.get("amount")
        category = request.form.get("category")
        
        if not amount or not category:
            return apology("must provide amount and category")
        
        db.execute("INSERT INTO expenses (user_id, amount, category) VALUES (?, ?, ?)", user_id, amount, category)
        flash("Expense added successfully!")
        return redirect("/")
    else:
        return render_template("add_expense.html")

@app.route("/set_budget", methods=["GET", "POST"])
@login_required
def set_budget():
    """Set a budget"""
    if request.method == "POST":
        user_id = session["user_id"]
        category = request.form.get("category")
        amount = request.form.get("amount")
        
        if not category or not amount:
            return apology("must provide category and amount")
        
        db.execute("INSERT INTO budgets (user_id, category, amount) VALUES (?, ?, ?)", user_id, category, amount)
        flash("Budget set successfully!")
        return redirect("/")
    else:
        return render_template("set_budget.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("must provide username", 400)
        if not password:
            return apology("must provide password", 400)
        if password != confirmation:
            return apology("passwords don't match", 400)

        # Query database if username already exist
        hash = generate_password_hash(password)
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
        except:
            return apology("username already exists", 400)

        # Query database for newly inserted user
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Remember which user logged in
        session["user_id"] = rows[0]["id"]

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Allow user to change password"""
    if request.method == "POST":
        # Get form inputs
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # Validate form inputs
        if not old_password or not new_password or not confirm_password:
            return apology("must provide all fields", 400)
        if new_password != confirm_password:
            return apology("new passwords do not match", 400)

        # Get user's current password hash from the database
        user = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=session["user_id"])[0]

        # Verify old password
        if not check_password_hash(user["hash"], old_password):
            return apology("old password is incorrect", 400)

        # Hash new password
        new_password_hash = generate_password_hash(new_password)

        # Update password in the database
        db.execute("UPDATE users SET hash = :new_password_hash WHERE id = :user_id",
                   new_password_hash=new_password_hash, user_id=session["user_id"])

        # Redirect to home page
        return redirect("/")

    else:
        return render_template("change_password.html")


@app.route("/set_goal", methods=["GET", "POST"])
@login_required
def set_goal():
    """Set a financial goal"""
    if request.method == "POST":
        user_id = session["user_id"]
        description = request.form.get("description")
        target_amount = request.form.get("target_amount")
        deadline = request.form.get("deadline")
        
        if not description or not target_amount or not deadline:
            return apology("must provide all fields")
        
        db.execute("INSERT INTO goals (user_id, description, target_amount, deadline) VALUES (?, ?, ?, ?)", user_id, description, target_amount, deadline)
        flash("Goal set successfully!")
        return redirect("/")
    else:
        return render_template("set_goal.html")

# Other existing routes (login, register, etc.) remain unchanged

if __name__ == "__main__":
    app.run(debug=True)
