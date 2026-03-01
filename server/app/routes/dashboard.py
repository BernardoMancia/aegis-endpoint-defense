from flask import Blueprint, render_template, session, redirect, url_for
from functools import wraps

dashboard_bp = Blueprint("dashboard", __name__)


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("soc_user"):
            return redirect(url_for("auth.login_page"))
        return f(*args, **kwargs)
    return decorated


@dashboard_bp.route("/")
@require_auth
def index():
    return render_template("dashboard.html",
                           current_user=session.get("soc_user"),
                           current_role=session.get("soc_role"),
                           current_display=session.get("soc_display"))


@dashboard_bp.route("/history")
@require_auth
def history():
    return render_template("history.html",
                           current_user=session.get("soc_user"),
                           current_role=session.get("soc_role"),
                           current_display=session.get("soc_display"))


@dashboard_bp.route("/agent/<int:agent_id>")
@require_auth
def agent_detail(agent_id):
    from models.agent import Agent
    agent = Agent.query.get_or_404(agent_id)
    return render_template("agent_detail.html",
                           agent=agent,
                           current_user=session.get("soc_user"),
                           current_role=session.get("soc_role"),
                           current_display=session.get("soc_display"))
