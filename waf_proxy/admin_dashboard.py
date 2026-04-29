from flask import Flask, render_template, request, jsonify, redirect, url_for
from database_manager import (
    init_db,
    add_log,
    is_ip_banned,
    ban_ip,
    unban_ip,
    get_attack_stats,
    get_banned_ips,
    get_all_logs,
) 
import os
from datetime import datetime, timedelta 

app = Flask(__name__)


@app.route("/")
def index():
    return redirect(url_for("admin_dashboard"))


@app.route("/admin")
def admin_dashboard():
    """Renders the main admin dashboard page."""
    return render_template("dashboard.html")


@app.route("/admin/logs")
def admin_logs():
    """Renders the logs page."""
    
    return render_template("logs.html")


@app.route("/api/stats")
def api_stats():
    """API endpoint to fetch statistics for the dashboard charts."""
    try:
        stats = get_attack_stats()
        return jsonify(stats)
    except Exception as e:
        print(f"Error in /api/stats: {e}")
        return jsonify({"error": "Could not retrieve stats"}), 500


@app.route("/api/logs")
def api_logs():
    try:
        limit = request.args.get("limit", 20, type=int)
        logs = get_all_logs(limit=limit)
        return jsonify(logs)
    except Exception as e:
        print(f"Error in /api/logs: {e}")
        return jsonify({"error": "Could not retrieve logs"}), 500


@app.route("/api/banned_ips")
def api_banned_ips():
    """API endpoint to fetch the list of currently banned IPs from database."""
    try:
        banned_ips_data = (
            get_banned_ips()
        )  

        for entry in banned_ips_data:
            if isinstance(entry.get("ban_timestamp"), datetime):
                entry["ban_timestamp"] = entry["ban_timestamp"].isoformat()

        return jsonify(banned_ips_data)
    except Exception as e:
        print(f"Error in /api/banned_ips: {e}")
        return jsonify({"error": "Could not retrieve banned IPs"}), 500


@app.route("/admin/manage_ip", methods=["POST"])
def manage_ip():
    """Handles IP banning and unbanning requests."""
    data = request.get_json()
    ip_address = data.get("ip_address")
    action = data.get("action")  
    reason = data.get("reason")

    if not ip_address or not action:
        return (
            jsonify({"success": False, "message": "Missing ip_address or action"}),
            400,
        )

    try:
        if action == "ban":
            if ban_ip(ip_address, reason):
                return jsonify(
                    {
                        "success": True,
                        "message": f"IP {ip_address} banned successfully.",
                    }
                )
            else:
                # Could be already banned or an error
                if is_ip_banned(ip_address):
                    return (
                        jsonify(
                            {
                                "success": False,
                                "message": f"IP {ip_address} is already banned.",
                            }
                        ),
                        409,
                    )
                else:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "message": f"Error banning IP {ip_address}.",
                            }
                        ),
                        500,
                    )
        elif action == "unban":
            if unban_ip(ip_address):
                return jsonify(
                    {
                        "success": True,
                        "message": f"IP {ip_address} unbanned successfully.",
                    }
                )
            else:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": f"IP {ip_address} was not found or could not be unbanned.",
                        }
                    ),
                    404,
                )
        else:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Invalid action specified. Use 'ban' or 'unban'.",
                    }
                ),
                400,
            )
    except Exception as e:
        print(f"Error in /admin/manage_ip: {e}")
        return (
            jsonify({"success": False, "message": "An internal error occurred."}),
            500,
        )


if __name__ == "__main__":
    if "DATABASE_URL" not in os.environ:
        print("DATABASE_URL environment variable not set. Using default SQLite.")
        os.environ["DATABASE_URL"] = "sqlite:///./waf_proxy/default.db"

    print(f"Database URL: {os.environ.get('DATABASE_URL')}")

    init_db()
    print("Database initialized.")

    port = int(os.environ.get("PORT", 5005))
    app.run(debug=True, host="0.0.0.0", port=port)
