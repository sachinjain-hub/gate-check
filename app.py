import os
import random
import io
import base64
from uuid import uuid4
from datetime import datetime, timedelta

from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import bcrypt
import qrcode
from twilio.rest import Client

# =====================================================
# APP CONFIG
# =====================================================
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

# =====================================================
# DATABASE CONFIG
# =====================================================
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://")

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# =====================================================
# TWILIO CONFIG
# =====================================================
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_FROM_NUMBER = os.environ.get("TWILIO_FROM_NUMBER")

twilio_client = None
if all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER]):
    twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

def send_sms(phone, message):
    if not twilio_client:
        return
    try:
        twilio_client.messages.create(
            body=message,
            from_=TWILIO_FROM_NUMBER,
            to=phone
        )
    except Exception as e:
        print("Twilio error:", e)

# =====================================================
# MODELS
# =====================================================
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(255))
    parents_phone = db.Column(db.String(20))
    role = db.Column(db.String(20), default="student")


class GatePassRequest(db.Model):
    __tablename__ = "gate_pass_requests"

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    student_name = db.Column(db.String(120))
    reason = db.Column(db.Text)
    out_date = db.Column(db.String(20))
    out_time = db.Column(db.String(20))
    status = db.Column(db.String(20), default="Pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    student = db.relationship("User", backref="requests")

# =====================================================
# ROUTES
# =====================================================
@app.route("/student", methods=["GET", "POST"])
def student():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])

    # ---------- OTP VERIFY ----------
    if request.method == "POST" and session.get("otp_phase"):
        if datetime.utcnow() > session.get("otp_expiry"):
            flash("OTP expired", "danger")
            session.pop("otp_phase")
            return redirect(url_for("student"))

        if request.form.get("otp") != str(session.get("otp")):
            flash("Invalid OTP", "danger")
            return redirect(url_for("student"))

        data = session["pending"]
        req = GatePassRequest(
            student_id=user.id,
            student_name=user.name,
            reason=data["reason"],
            out_date=data["out_date"],
            out_time=data["out_time"]
        )
        db.session.add(req)
        db.session.commit()

        session.pop("otp_phase")
        session.pop("otp")
        session.pop("otp_expiry")
        session.pop("pending")

        flash("Gate pass request submitted", "success")
        return redirect(url_for("student"))

    # ---------- SEND OTP ----------
    if request.method == "POST":
        otp = random.randint(100000, 999999)
        session["otp"] = otp
        session["otp_phase"] = True
        session["otp_expiry"] = datetime.utcnow() + timedelta(minutes=5)
        session["pending"] = {
            "reason": request.form["reason"],
            "out_date": request.form["out_date"],
            "out_time": request.form["out_time"]
        }

        send_sms(user.parents_phone, f"OTP for gate pass is {otp}")
        flash("OTP sent to parent's mobile number", "info")
        return redirect(url_for("student"))

    requests_list = GatePassRequest.query.filter_by(student_id=user.id).all()

    return render_template(
        "student.html",
        student_name=user.name,
        requests_list=requests_list,
        otp_required=session.get("otp_phase", False)
    )

# =====================================================
# LOGIN / LOGOUT (SIMPLE)
# =====================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()
        if user and bcrypt.checkpw(
            request.form["password"].encode(),
            user.password.encode()
        ):
            session["user_id"] = user.id
            session["role"] = user.role
            return redirect(url_for("student"))

        flash("Invalid credentials", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# =====================================================
# MAIN
# =====================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

