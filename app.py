import csv
import io
from datetime import datetime, date, timedelta
from functools import wraps

from flask import (
    Flask, render_template, redirect, url_for, flash, request,
    jsonify, Response, abort, session, g
)
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
import database as db_layer
from database import REGIONS, THREAT_TYPES, SEVERITIES

VALID_ROLES = ("admin", "analyst", "user")


class CurrentUser:
    """Lightweight wrapper around a users row for templates & role checks."""

    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self.email = row["email"]
        self.role = row["role"]
        self.active_flag = bool(row["active_flag"])
        self.created_at = row["created_at"]
        self.is_authenticated = True

    def is_admin(self):
        return self.role == "admin"

    def is_analyst(self):
        return self.role == "analyst"

    def can_export(self):
        return self.role in ("admin", "analyst")

    def can_manage_users(self):
        return self.role == "admin"


class AnonymousUser:
    is_authenticated = False
    role = None

    def can_export(self):
        return False

    def can_manage_users(self):
        return False


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db_layer.init_app(app)

    with app.app_context():
        db_layer.init_db(app)

    register_hooks(app)
    register_routes(app)
    return app


def register_hooks(app):
    @app.before_request
    def load_logged_in_user():
        user_id = session.get("user_id")
        if user_id is None:
            g.user = AnonymousUser()
            return
        row = db_layer.get_db().execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        g.user = CurrentUser(row) if row else AnonymousUser()

    @app.context_processor
    def inject_user():
        return {"current_user": g.user}


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not g.user.is_authenticated:
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator


def parse_filters(args):
    filters = {}
    region = args.get("region")
    threat_type = args.get("threat_type")
    severity = args.get("severity")
    start_date = args.get("start_date")
    end_date = args.get("end_date")

    if region and region != "all":
        filters["region"] = region
    if threat_type and threat_type != "all":
        filters["threat_type"] = threat_type
    if severity and severity != "all":
        filters["severity"] = severity

    try:
        filters["start_date"] = (
            datetime.strptime(start_date, "%Y-%m-%d").date()
            if start_date else date.today() - timedelta(days=90)
        )
    except ValueError:
        filters["start_date"] = date.today() - timedelta(days=90)

    try:
        filters["end_date"] = (
            datetime.strptime(end_date, "%Y-%m-%d").date()
            if end_date else date.today()
        )
    except ValueError:
        filters["end_date"] = date.today()

    return filters


def build_where(filters):
    """Returns (where_sql, params) shared across all stats queries."""
    clauses = ["event_date >= ?", "event_date <= ?"]
    params = [filters["start_date"].isoformat(), filters["end_date"].isoformat()]

    if "region" in filters:
        clauses.append("region = ?")
        params.append(filters["region"])
    if "threat_type" in filters:
        clauses.append("threat_type = ?")
        params.append(filters["threat_type"])
    if "severity" in filters:
        clauses.append("severity = ?")
        params.append(filters["severity"])

    return " AND ".join(clauses), params


def register_routes(app):

    # ------------------------------------------------------------------ #
    # Auth
    # ------------------------------------------------------------------ #
    @app.route("/")
    def index():
        if g.user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            row = db_layer.get_db().execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            if row and check_password_hash(row["password_hash"], password) and row["active_flag"]:
                session.clear()
                session["user_id"] = row["id"]
                flash(f"Welcome back, {row['username']}.", "success")
                next_page = request.args.get("next")
                return redirect(next_page or url_for("dashboard"))
            flash("Invalid username or password.", "danger")
        return render_template("login.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if g.user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")

            db = db_layer.get_db()
            error = None
            if not username or not email or not password:
                error = "All fields are required."
            elif password != confirm:
                error = "Passwords do not match."
            elif db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
                error = "Username already taken."
            elif db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
                error = "Email already registered."

            if error:
                flash(error, "danger")
                return render_template("register.html")

            db.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'user')",
                (username, email, generate_password_hash(password)),
            )
            db.commit()
            flash("Account created. You can now log in.", "success")
            return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/logout")
    @login_required
    def logout():
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    # ------------------------------------------------------------------ #
    # Dashboard
    # ------------------------------------------------------------------ #
    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template(
            "dashboard.html",
            regions=REGIONS,
            threat_types=THREAT_TYPES,
            severities=SEVERITIES,
        )

    # ------------------------------------------------------------------ #
    # Admin: user management
    # ------------------------------------------------------------------ #
    @app.route("/admin/users")
    @role_required("admin")
    def admin_users():
        rows = db_layer.get_db().execute(
            "SELECT * FROM users ORDER BY created_at DESC"
        ).fetchall()
        return render_template("admin.html", users=rows)

    @app.route("/admin/users/<int:user_id>/role", methods=["POST"])
    @role_required("admin")
    def admin_update_role(user_id):
        new_role = request.form.get("role")
        db = db_layer.get_db()
        target = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            abort(404)
        if new_role not in VALID_ROLES:
            flash("Invalid role.", "danger")
        else:
            db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
            db.commit()
            flash(f"Updated {target['username']}'s role to {new_role}.", "success")
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/<int:user_id>/toggle_active", methods=["POST"])
    @role_required("admin")
    def admin_toggle_active(user_id):
        db = db_layer.get_db()
        target = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            abort(404)
        if target["id"] == g.user.id:
            flash("You cannot deactivate your own account.", "warning")
        else:
            new_state = 0 if target["active_flag"] else 1
            db.execute("UPDATE users SET active_flag = ? WHERE id = ?", (new_state, user_id))
            db.commit()
            flash(f"{target['username']} has been {'activated' if new_state else 'deactivated'}.", "success")
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
    @role_required("admin")
    def admin_delete_user(user_id):
        db = db_layer.get_db()
        target = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            abort(404)
        if target["id"] == g.user.id:
            flash("You cannot delete your own account.", "warning")
        else:
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
            flash(f"Deleted user {target['username']}.", "success")
        return redirect(url_for("admin_users"))

    # ------------------------------------------------------------------ #
    # API: metadata
    # ------------------------------------------------------------------ #
    @app.route("/api/meta")
    @login_required
    def api_meta():
        return jsonify({
            "regions": REGIONS,
            "threat_types": THREAT_TYPES,
            "severities": SEVERITIES,
            "role": g.user.role,
            "can_export": g.user.can_export(),
            "can_manage_users": g.user.can_manage_users(),
        })

    # ------------------------------------------------------------------ #
    # API: filtered / paginated raw events
    # ------------------------------------------------------------------ #
    @app.route("/api/threats")
    @login_required
    def api_threats():
        filters = parse_filters(request.args)
        where_sql, params = build_where(filters)

        page = request.args.get("page", 1, type=int)
        per_page = 20 if g.user.role == "user" else 50
        offset = (page - 1) * per_page

        db = db_layer.get_db()
        total = db.execute(
            f"SELECT COUNT(*) AS c FROM threat_events WHERE {where_sql}", params
        ).fetchone()["c"]

        rows = db.execute(
            f"""SELECT * FROM threat_events WHERE {where_sql}
                ORDER BY event_date DESC LIMIT ? OFFSET ?""",
            params + [per_page, offset],
        ).fetchall()

        pages = max(1, (total + per_page - 1) // per_page)
        items = [dict(r) for r in rows]

        return jsonify({
            "items": items,
            "total": total,
            "page": page,
            "pages": pages,
        })

    # ------------------------------------------------------------------ #
    # API: summary KPIs
    # ------------------------------------------------------------------ #
    @app.route("/api/stats/summary")
    @login_required
    def api_stats_summary():
        filters = parse_filters(request.args)
        where_sql, params = build_where(filters)
        db = db_layer.get_db()

        totals = db.execute(
            f"""SELECT COALESCE(SUM(incident_count), 0) AS total_incidents,
                       COUNT(*) AS total_events
                FROM threat_events WHERE {where_sql}""",
            params,
        ).fetchone()

        critical_where = where_sql + " AND severity = 'Critical'"
        critical = db.execute(
            f"SELECT COALESCE(SUM(incident_count), 0) AS c FROM threat_events WHERE {critical_where}",
            params,
        ).fetchone()["c"]

        top_region = db.execute(
            f"""SELECT region, SUM(incident_count) AS total FROM threat_events
                WHERE {where_sql} GROUP BY region ORDER BY total DESC LIMIT 1""",
            params,
        ).fetchone()

        top_type = db.execute(
            f"""SELECT threat_type, SUM(incident_count) AS total FROM threat_events
                WHERE {where_sql} GROUP BY threat_type ORDER BY total DESC LIMIT 1""",
            params,
        ).fetchone()

        return jsonify({
            "total_incidents": int(totals["total_incidents"] or 0),
            "total_events": int(totals["total_events"] or 0),
            "critical_incidents": int(critical or 0),
            "top_region": top_region["region"] if top_region else None,
            "top_threat_type": top_type["threat_type"] if top_type else None,
        })

    # ------------------------------------------------------------------ #
    # API: trend over time
    # ------------------------------------------------------------------ #
    @app.route("/api/stats/trend")
    @login_required
    def api_stats_trend():
        filters = parse_filters(request.args)
        where_sql, params = build_where(filters)
        rows = db_layer.get_db().execute(
            f"""SELECT event_date, SUM(incident_count) AS total FROM threat_events
                WHERE {where_sql} GROUP BY event_date ORDER BY event_date ASC""",
            params,
        ).fetchall()
        return jsonify({
            "labels": [r["event_date"] for r in rows],
            "values": [int(r["total"]) for r in rows],
        })

    # ------------------------------------------------------------------ #
    # API: by region
    # ------------------------------------------------------------------ #
    @app.route("/api/stats/by_region")
    @login_required
    def api_stats_by_region():
        filters = parse_filters(request.args)
        where_sql, params = build_where(filters)
        rows = db_layer.get_db().execute(
            f"""SELECT region, SUM(incident_count) AS total FROM threat_events
                WHERE {where_sql} GROUP BY region ORDER BY total DESC""",
            params,
        ).fetchall()
        return jsonify({
            "labels": [r["region"] for r in rows],
            "values": [int(r["total"]) for r in rows],
        })

    # ------------------------------------------------------------------ #
    # API: by threat type
    # ------------------------------------------------------------------ #
    @app.route("/api/stats/by_type")
    @login_required
    def api_stats_by_type():
        filters = parse_filters(request.args)
        where_sql, params = build_where(filters)
        rows = db_layer.get_db().execute(
            f"""SELECT threat_type, SUM(incident_count) AS total FROM threat_events
                WHERE {where_sql} GROUP BY threat_type ORDER BY total DESC""",
            params,
        ).fetchall()
        return jsonify({
            "labels": [r["threat_type"] for r in rows],
            "values": [int(r["total"]) for r in rows],
        })

    # ------------------------------------------------------------------ #
    # API: by severity
    # ------------------------------------------------------------------ #
    @app.route("/api/stats/by_severity")
    @login_required
    def api_stats_by_severity():
        filters = parse_filters(request.args)
        where_sql, params = build_where(filters)
        rows = db_layer.get_db().execute(
            f"""SELECT severity, SUM(incident_count) AS total FROM threat_events
                WHERE {where_sql} GROUP BY severity""",
            params,
        ).fetchall()
        data = {r["severity"]: int(r["total"]) for r in rows}
        ordered = [data.get(s, 0) for s in SEVERITIES]
        return jsonify({"labels": list(SEVERITIES), "values": ordered})

    # ------------------------------------------------------------------ #
    # API: region x severity heatmap
    # ------------------------------------------------------------------ #
    @app.route("/api/stats/heatmap")
    @login_required
    def api_stats_heatmap():
        filters = parse_filters(request.args)
        where_sql, params = build_where(filters)
        rows = db_layer.get_db().execute(
            f"""SELECT region, severity, SUM(incident_count) AS total FROM threat_events
                WHERE {where_sql} GROUP BY region, severity""",
            params,
        ).fetchall()

        matrix = {region: {sev: 0 for sev in SEVERITIES} for region in REGIONS}
        for r in rows:
            if r["region"] in matrix and r["severity"] in matrix[r["region"]]:
                matrix[r["region"]][r["severity"]] = int(r["total"])

        return jsonify({"regions": REGIONS, "severities": SEVERITIES, "matrix": matrix})

    # ------------------------------------------------------------------ #
    # Export (analyst + admin only)
    # ------------------------------------------------------------------ #
    @app.route("/api/export.csv")
    @login_required
    def api_export_csv():
        if not g.user.can_export():
            abort(403)
        filters = parse_filters(request.args)
        where_sql, params = build_where(filters)
        rows = db_layer.get_db().execute(
            f"""SELECT * FROM threat_events WHERE {where_sql} ORDER BY event_date DESC""",
            params,
        ).fetchall()

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Date", "Region", "Country", "Threat Type", "Severity", "Incident Count", "Source", "Description"])
        for r in rows:
            writer.writerow([
                r["event_date"], r["region"], r["country"], r["threat_type"],
                r["severity"], r["incident_count"], r["source"], r["description"],
            ])

        response = Response(buf.getvalue(), mimetype="text/csv")
        response.headers["Content-Disposition"] = "attachment; filename=threat_export.csv"
        return response

    # ------------------------------------------------------------------ #
    # Error handlers
    # ------------------------------------------------------------------ #
    @app.errorhandler(403)
    def forbidden(e):
        return render_template("error.html", code=403, message="You don't have permission to view this page."), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404, message="Page not found."), 404


app = create_app()


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
