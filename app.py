from __future__ import annotations

import os
from datetime import datetime
from typing import Callable, Iterable, Optional

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")

RESET_CODE = os.environ.get("RESET_CODE", "RESET123")

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'student' | 'admin' | 'principal'

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Staff(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)


class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)


class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.Integer, db.ForeignKey("staff.id"), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey("subject.id"), nullable=False)
    __table_args__ = (db.UniqueConstraint("staff_id", "subject_id", name="uix_staff_subject"),)

    staff = db.relationship("Staff")
    subject = db.relationship("Subject")


class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    staff_id = db.Column(db.Integer, db.ForeignKey("staff.id"), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey("subject.id"), nullable=False)
    rating = db.Column(db.String(20), nullable=False)  # 'Average' | 'Good' | 'Excellent'
    comments = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    student = db.relationship("User")
    staff = db.relationship("Staff")
    subject = db.relationship("Subject")


def bootstrap_data() -> None:
    db.create_all()

    if User.query.count() > 0:
        return

    # Users
    admin = User(username="admin", role="admin")
    admin.set_password("admin123")
    principal = User(username="principal", role="principal")
    principal.set_password("principal123")
    student = User(username="student1", role="student")
    student.set_password("pass123")

    db.session.add_all([admin, principal, student])

    # Staff and subjects
    staff_members = [
        Staff(name="Dr. Smith"),
        Staff(name="Prof. Johnson"),
        Staff(name="Ms. Lee"),
    ]
    subjects = [
        Subject(name="Mathematics"),
        Subject(name="Physics"),
        Subject(name="Computer Science"),
    ]
    db.session.add_all(staff_members + subjects)
    db.session.flush()

    # Assignments (staff -> subjects)
    assignments: list[Assignment] = [
        Assignment(staff_id=staff_members[0].id, subject_id=subjects[0].id),
        Assignment(staff_id=staff_members[0].id, subject_id=subjects[1].id),
        Assignment(staff_id=staff_members[1].id, subject_id=subjects[1].id),
        Assignment(staff_id=staff_members[1].id, subject_id=subjects[2].id),
        Assignment(staff_id=staff_members[2].id, subject_id=subjects[0].id),
        Assignment(staff_id=staff_members[2].id, subject_id=subjects[2].id),
    ]
    db.session.add_all(assignments)

    db.session.commit()


def login_required(allowed_roles: Optional[Iterable[str]] = None) -> Callable:
    def decorator(fn: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            user_id = session.get("user_id")
            role = session.get("role")
            if not user_id or not role:
                return redirect(url_for("index"))
            if allowed_roles is not None and role not in allowed_roles:
                abort(403)
            return fn(*args, **kwargs)

        # Preserve function identity for Flask
        wrapper.__name__ = fn.__name__
        return wrapper

    return decorator


@app.route("/")
def index():
    return render_template("index.html")


# ------------------ Student Auth ------------------
@app.route("/student/login", methods=["GET", "POST"])
def student_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username, role="student").first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            session["role"] = user.role
            return redirect(url_for("student_dashboard"))
        flash("Invalid credentials", "error")
    return render_template("student_login.html")


@app.route("/student/forgot", methods=["GET", "POST"])
def student_forgot_password():
    message = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        reset_code = request.form.get("reset_code", "").strip()
        new_password = request.form.get("new_password", "")
        user = User.query.filter_by(username=username, role="student").first()
        if not user:
            message = "If the account exists, a reset will be processed."
        elif reset_code != RESET_CODE:
            message = "Invalid reset code. Contact administrator."
        else:
            user.set_password(new_password)
            db.session.commit()
            flash("Password reset successful. Please log in.")
            return redirect(url_for("student_login"))
    return render_template("forgot_password.html", message=message)


@app.route("/student/logout")
def student_logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/student/dashboard")
@login_required(allowed_roles=["student"])
def student_dashboard():
    assignments = (
        db.session.query(Assignment)
        .join(Staff, Assignment.staff_id == Staff.id)
        .join(Subject, Assignment.subject_id == Subject.id)
        .order_by(Staff.name.asc(), Subject.name.asc())
        .all()
    )
    return render_template("student_dashboard.html", assignments=assignments)


@app.route("/feedback/<int:staff_id>/<int:subject_id>", methods=["GET", "POST"])
@login_required(allowed_roles=["student"])
def feedback_form(staff_id: int, subject_id: int):
    staff = Staff.query.get_or_404(staff_id)
    subject = Subject.query.get_or_404(subject_id)

    # Ensure this staff-subject combination is valid
    exists = Assignment.query.filter_by(staff_id=staff_id, subject_id=subject_id).first()
    if not exists:
        abort(404)

    if request.method == "POST":
        rating = request.form.get("rating")
        comments = request.form.get("comments", "").strip()
        if rating not in {"Average", "Good", "Excellent"}:
            flash("Please select a rating.", "error")
        else:
            fb = Feedback(
                student_id=session.get("user_id"),
                staff_id=staff_id,
                subject_id=subject_id,
                rating=rating,
                comments=comments or None,
            )
            db.session.add(fb)
            db.session.commit()
            flash("Thank you for your feedback!")
            return redirect(url_for("student_dashboard"))

    return render_template("feedback_form.html", staff=staff, subject=subject)


# ------------------ Admin/Principal ------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter(User.username == username, User.role.in_(["admin", "principal"]))
        user = user.first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            session["role"] = user.role
            return redirect(url_for("admin_dashboard"))
        flash("Invalid credentials", "error")
    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("index"))


def _rating_value(r: str) -> int:
    return {"Average": 1, "Good": 2, "Excellent": 3}.get(r, 0)


def _summary_label(avg_score: float) -> str:
    if avg_score >= 2.5:
        return "Excellent"
    if avg_score >= 1.5:
        return "Good"
    return "Average"


@app.route("/admin/dashboard")
@login_required(allowed_roles=["admin", "principal"])
def admin_dashboard():
    staffs = Staff.query.order_by(Staff.name.asc()).all()
    summary_rows = []
    for s in staffs:
        fbs = Feedback.query.filter_by(staff_id=s.id).all()
        count_avg = sum(1 for f in fbs if f.rating == "Average")
        count_good = sum(1 for f in fbs if f.rating == "Good")
        count_ex = sum(1 for f in fbs if f.rating == "Excellent")
        total = len(fbs)
        avg_score = (sum(_rating_value(f.rating) for f in fbs) / total) if total else 0.0
        summary_rows.append(
            {
                "staff": s,
                "num_average": count_avg,
                "num_good": count_good,
                "num_excellent": count_ex,
                "total": total,
                "avg_score": avg_score,
                "summary": _summary_label(avg_score) if total else "No feedback",
            }
        )
    return render_template("admin_dashboard.html", rows=summary_rows)


@app.route("/admin/staff/<int:staff_id>")
@login_required(allowed_roles=["admin", "principal"])
def staff_feedback_detail(staff_id: int):
    staff = Staff.query.get_or_404(staff_id)
    feedbacks = (
        Feedback.query.filter_by(staff_id=staff_id)
        .order_by(Feedback.created_at.desc())
        .all()
    )

    # Aggregate by subject
    subject_map = {sub.id: sub for sub in Subject.query.all()}
    by_subject: dict[int, dict] = {}
    for f in feedbacks:
        entry = by_subject.setdefault(
            f.subject_id,
            {"subject": subject_map.get(f.subject_id), "avg": 0, "good": 0, "excellent": 0, "total": 0},
        )
        if f.rating == "Average":
            entry["avg"] += 1
        elif f.rating == "Good":
            entry["good"] += 1
        elif f.rating == "Excellent":
            entry["excellent"] += 1
        entry["total"] += 1

    return render_template(
        "staff_feedback_detail.html",
        staff=staff,
        feedbacks=feedbacks,
        by_subject=by_subject,
    )


@app.before_request
def ensure_db_and_seed():
    # Create and seed once per process start
    if not hasattr(app, "_bootstrapped"):
        bootstrap_data()
        app._bootstrapped = True


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)

