from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import ipaddress
import os
import re
import threading
import time
from datetime import datetime, date

# === MySQL / MariaDB (ตัวเดียวกับที่เปิดดูใน phpMyAdmin) ===
import pymysql
from pymysql.cursors import DictCursor
from werkzeug.security import check_password_hash, generate_password_hash

# === นำเข้าไลบรารีสำหรับเชื่อมต่อ EVE-NG ===
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

app = Flask(__name__)
# secret_key ใช้เซ็น session cookie เพื่อให้ Flask ตรวจได้ว่าข้อมูล session ไม่ถูกแก้จากฝั่งผู้ใช้
app.secret_key = "network-monitor-secret-key-2024"

# === ตั้งค่าการเชื่อมต่อ MySQL ===
# ฐานข้อมูล MySQL อยู่บน Ubuntu (VMware) ที่ IP 192.168.91.131
# ต้องสร้าง user ชื่อ netmon บน MySQL แล้วใส่รหัสผ่านให้ตรงกัน
# (หรือกำหนดผ่าน environment variable DB_HOST / DB_USER / DB_PASSWORD)
DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "192.168.91.131"),
    "port": int(os.environ.get("DB_PORT", 3306)),
    "user": os.environ.get("DB_USER", "netmon"),
    "password": os.environ.get("DB_PASSWORD", "CHANGE_ME"),
    "database": os.environ.get("DB_NAME", "network_monitor"),
    "charset": "utf8mb4",
    "cursorclass": DictCursor,
    "autocommit": True,
}

# === ตั้งค่ารหัสผ่านสำหรับเข้าอุปกรณ์ใน EVE-NG ===
EVE_DEVICE_USER = 'admin'      # ตรงกับ username admin บน Router/Switch
EVE_DEVICE_PASS = '1234'
EVE_DEVICE_TYPE = 'cisco_ios'  # ประเภทอุปกรณ์ Cisco

# === ตั้งค่าการ SSH ไปยัง Router ที่ใช้ตรวจสอบสถานะ ===
ROUTER_SSH_HOST = os.environ.get("ROUTER_SSH_HOST", "192.168.91.130")
ROUTER_SSH_USER = os.environ.get("ROUTER_SSH_USER")
ROUTER_SSH_PASS = os.environ.get("ROUTER_SSH_PASS")

TIME_FMT = "%Y-%m-%d %H:%M:%S"


def now_str():
    return datetime.now().strftime(TIME_FMT)


def get_db():
    return pymysql.connect(**DB_CONFIG)


def query(sql, args=(), one=False):
    """SELECT: คืนค่าเป็น list ของ dict (หรือ dict เดียวถ้า one=True)"""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, args)
            return cur.fetchone() if one else cur.fetchall()
    finally:
        conn.close()


def execute(sql, args=()):
    """INSERT / UPDATE / DELETE (autocommit)"""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, args)
    finally:
        conn.close()


def jsonable(rows):
    """แปลง DATETIME เป็นสตริง 'YYYY-MM-DD HH:MM:SS' ให้หน้าเว็บแสดงผลเหมือนเดิม"""
    out = []
    for r in rows:
        r = dict(r)
        for k, v in r.items():
            if isinstance(v, (datetime, date)):
                r[k] = v.strftime(TIME_FMT)
        out.append(r)
    return out


def init_db():
    """สร้างตารางที่ระบบใช้เมื่อยังไม่มี และสร้างบัญชีหลักครั้งแรก"""
    conn = pymysql.connect(**DB_CONFIG)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS `devices` (
                    `id`           INT UNSIGNED NOT NULL AUTO_INCREMENT,
                    `name`         VARCHAR(100) NOT NULL,
                    `ip_address`   VARCHAR(45)  NOT NULL,
                    `type`         VARCHAR(30)  NOT NULL,
                    `category`     VARCHAR(50)  NOT NULL,
                    `location`     VARCHAR(100) NOT NULL DEFAULT 'Server Room',
                    `status`       VARCHAR(10)  NOT NULL DEFAULT 'Online',
                    `last_updated` DATETIME     NOT NULL,
                    `parent_id`    INT UNSIGNED DEFAULT NULL,
                    PRIMARY KEY (`id`),
                    KEY `idx_devices_parent` (`parent_id`),
                    CONSTRAINT `fk_devices_parent` FOREIGN KEY (`parent_id`)
                        REFERENCES `devices` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS `activity_log` (
                    `id`        INT UNSIGNED NOT NULL AUTO_INCREMENT,
                    `user`      VARCHAR(50)  NOT NULL,
                    `action`    VARCHAR(50)  NOT NULL,
                    `target`    VARCHAR(100) NOT NULL,
                    `details`   VARCHAR(255) NOT NULL,
                    `timestamp` DATETIME     NOT NULL,
                    PRIMARY KEY (`id`),
                    KEY `idx_activity_time` (`timestamp`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS `device_status_history` (
                    `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                    `device_id`   INT UNSIGNED NOT NULL,
                    `device_name` VARCHAR(100) NOT NULL,
                    `ip_address`  VARCHAR(45)  NOT NULL,
                    `device_type` VARCHAR(30)  NOT NULL,
                    `status`      VARCHAR(10)  NOT NULL,
                    `checked_at`  DATETIME     NOT NULL,
                    PRIMARY KEY (`id`),
                    KEY `idx_status_history_checked_at` (`checked_at`),
                    KEY `idx_status_history_device_time` (`device_id`, `checked_at`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS `admin_users` (
                    `id`            INT UNSIGNED NOT NULL AUTO_INCREMENT,
                    `username`      VARCHAR(50)  NOT NULL,
                    `password_hash` VARCHAR(255) NOT NULL,
                    `created_at`    DATETIME     NOT NULL,
                    `updated_at`    DATETIME     NOT NULL,
                    PRIMARY KEY (`id`),
                    UNIQUE KEY `uq_admin_users_username` (`username`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            # สร้าง admin01 เฉพาะเมื่อยังไม่มีบัญชี โดยบันทึกรหัสผ่านเป็น hash ไม่เก็บรหัสจริง
            cur.execute("SELECT id FROM admin_users WHERE username=%s", ("admin01",))
            if not cur.fetchone():
                cur.execute(
                    """
                    INSERT INTO admin_users (username, password_hash, created_at, updated_at)
                    VALUES (%s, %s, %s, %s)
                    """,
                    ("admin01", generate_password_hash("1234"), now_str(), now_str()),
                )
        conn.commit()
    finally:
        conn.close()


def add_activity_log(user, action, target, details):
    try:
        execute(
            "INSERT INTO activity_log (`user`, `action`, `target`, `details`, `timestamp`) VALUES (%s, %s, %s, %s, %s)",
            (user, action, target, details, now_str()),
        )
    except Exception:
        pass


# === ฟังก์ชันสำหรับต่อเข้า EVE-NG ===
def fetch_status_from_eve(ip_address):
    device_config = {
        'device_type': EVE_DEVICE_TYPE,
        'host': ip_address,
        'username': EVE_DEVICE_USER,
        'password': EVE_DEVICE_PASS,
        'secret': EVE_DEVICE_PASS,
        'timeout': 15,
        'auth_timeout': 15,
        'banner_timeout': 15,
        'global_delay_factor': 2
    }
    try:
        net_connect = ConnectHandler(**device_config)
        output = net_connect.send_command('show ip interface brief')
        net_connect.disconnect()
        return "Online", output
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        return "Offline", str(e)
    except Exception as e:
        return "Offline", str(e)


def check_devices_from_router(devices):
    targets = []
    statuses = {}
    for device in devices:
        try:
            target = str(ipaddress.ip_address(device["ip_address"]))
        except ValueError:
            statuses[device["id"]] = "Unknown"
        else:
            targets.append((device["id"], target))

    if not targets:
        return statuses

    router_config = {
        "device_type": "cisco_ios",
        "host": ROUTER_SSH_HOST,
        "username": ROUTER_SSH_USER,
        "password": ROUTER_SSH_PASS,
        "timeout": 10,
        "auth_timeout": 10,
        "banner_timeout": 10,
        "fast_cli": False,
    }
    net_connect = ConnectHandler(**router_config)
    try:
        for device_id, target in targets:
            output = net_connect.send_command(
                f"ping {target} repeat 1 timeout 1",
                read_timeout=5,
            )
            match = re.search(
                r"Success rate is \d+ percent \((\d+)/(\d+)\)",
                output,
                re.IGNORECASE,
            )
            if not match:
                raise RuntimeError(f"Unexpected ping response from router for {target}")
            statuses[device_id] = "Online" if int(match.group(1)) > 0 else "Offline"
    finally:
        net_connect.disconnect()

    return statuses


def collect_device_statuses(record_history=False):
    # โหลดรายการอุปกรณ์จากฐานข้อมูล แล้วตรวจสถานะผ่าน Router
    devices = query("SELECT id, name, ip_address, type FROM devices ORDER BY id")
    if not devices:
        return
    if not ROUTER_SSH_USER or not ROUTER_SSH_PASS:
        raise RuntimeError("Set ROUTER_SSH_USER and ROUTER_SSH_PASS before collecting device status.")

    statuses = check_devices_from_router(devices)
    checked_at = now_str()
    conn = get_db()
    try:
        # อัปเดตสถานะล่าสุดทุกครั้งที่ตรวจ และบันทึกประวัติเฉพาะรอบที่กำหนด
        conn.begin()
        with conn.cursor() as cur:
            cur.executemany(
                "UPDATE devices SET status=%s, last_updated=%s WHERE id=%s",
                [(statuses[dev["id"]], checked_at, dev["id"]) for dev in devices],
            )
            if record_history:
                cur.executemany(
                    """
                    INSERT INTO device_status_history
                        (device_id, device_name, ip_address, device_type, status, checked_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    [
                        (
                            dev["id"], dev["name"], dev["ip_address"], dev["type"],
                            statuses[dev["id"]], checked_at,
                        )
                        for dev in devices
                    ],
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def status_history_collector():
    # ทำงานเบื้องหลัง: ตรวจสถานะทุกประมาณ 5 วินาที และบันทึกประวัติทุก 60 วินาที
    next_history_at = time.monotonic()
    while True:
        started_at = time.monotonic()
        try:
            record_history = started_at >= next_history_at
            collect_device_statuses(record_history=record_history)
            if record_history:
                next_history_at = time.monotonic() + 60
        except Exception:
            app.logger.exception("Unable to collect shared device statuses from the router")
        time.sleep(max(0, 5 - (time.monotonic() - started_at)))


@app.route("/")
def index():
    if "user" in session: return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # อ่านข้อมูลจากฟอร์ม; strip ช่องว่างเฉพาะชื่อผู้ใช้ ไม่แก้ค่ารหัสผ่าน
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        # Keep the old login usable during migration to the new admin01 account.
        account_name = "admin01" if username == "admin" and password == "1234" else username
        # ดึง hash จากฐานข้อมูลแล้วตรวจด้วย check_password_hash ไม่เปรียบเทียบรหัสแบบข้อความตรง ๆ
        admin = query(
            "SELECT username, password_hash FROM admin_users WHERE username=%s",
            (account_name,),
            one=True,
        )
        if admin and check_password_hash(admin["password_hash"], password):
            # เก็บชื่อผู้ใช้ใน session เพื่อใช้ตรวจสิทธิ์ในหน้าที่ต้องล็อกอิน
            session["user"] = admin["username"]
            add_activity_log(admin["username"], "Login", "System", "User logged in successfully")
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/logout")
def logout():
    # บันทึกกิจกรรมก่อนล้าง session แล้วส่งผู้ใช้ออกจากระบบ
    user = session.get("user", "Unknown")
    add_activity_log(user, "Logout", "System", "User logged out")
    session.pop("user", None)
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    # ห้ามเข้าหน้า Dashboard หากยังไม่มี session ผู้ใช้ที่ล็อกอิน
    if "user" not in session: return redirect(url_for("login"))
    return render_template("dashboard.html")


@app.route("/devices")
def devices():
    if "user" not in session: return redirect(url_for("login"))
    return render_template("devices.html")


@app.route("/devices/<int:id>")
def device_detail(id):
    if "user" not in session: return redirect(url_for("login"))
    dev = query("SELECT * FROM devices WHERE id=%s", (id,), one=True)
    if not dev: return "Device not found", 404
    return render_template("device_detail.html", device=dev)


@app.route("/activity")
def activity():
    if "user" not in session: return redirect(url_for("login"))
    return render_template("activity.html")


@app.route("/admin/manage", methods=["GET", "POST"])
def admin_manage():
    if "user" not in session:
        return redirect(url_for("login"))
    if session.get("user") != "admin01":
        return "Forbidden", 403

    message = None
    error = None
    reset_target = ""

    if request.method == "POST":
        action = request.form.get("action")
        if action == "reset-admin-password":
            reset_target = (request.form.get("target_username") or "").strip()
            new_password = request.form.get("new_password") or ""
            confirm_password = request.form.get("confirm_password") or ""
            target_admin = query(
                "SELECT username FROM admin_users WHERE username=%s",
                (reset_target,),
                one=True,
            )

            if reset_target == "admin01":
                error = "Use the Change admin01 password option to update this account"
            elif not target_admin:
                error = "Admin account was not found"
            elif len(new_password) < 4:
                error = "New password must be at least 4 characters"
            elif new_password != confirm_password:
                error = "New password and confirmation do not match"
            else:
                execute(
                    "UPDATE admin_users SET password_hash=%s, updated_at=%s WHERE username=%s",
                    (generate_password_hash(new_password), now_str(), reset_target),
                )
                add_activity_log(
                    session["user"],
                    "Reset Admin Password",
                    reset_target,
                    f"Reset password for admin account: {reset_target}",
                )
                message = f"Password for '{reset_target}' was reset successfully"
        elif action == "change-password":
            current_password = request.form.get("current_password") or ""
            new_password = request.form.get("new_password") or ""
            confirm_password = request.form.get("confirm_password") or ""
            admin = query(
                "SELECT password_hash FROM admin_users WHERE username=%s",
                ("admin01",),
                one=True,
            )

            if not admin or not check_password_hash(admin["password_hash"], current_password):
                error = "Current password is incorrect"
            elif len(new_password) < 4:
                error = "New password must be at least 4 characters"
            elif new_password != confirm_password:
                error = "New password and confirmation do not match"
            else:
                execute(
                    "UPDATE admin_users SET password_hash=%s, updated_at=%s WHERE username=%s",
                    (generate_password_hash(new_password), now_str(), "admin01"),
                )
                message = "Password updated successfully"
        elif action == "add-admin":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""

            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,50}", username):
                error = "Username must be 3-50 characters using letters, numbers, ., _ or -"
            elif username.lower() == "admin":
                error = "Username 'admin' is reserved"
            elif len(password) < 4:
                error = "Password must be at least 4 characters"
            elif query("SELECT id FROM admin_users WHERE username=%s", (username,), one=True):
                error = f"Username '{username}' already exists"
            else:
                try:
                    execute(
                        """
                        INSERT INTO admin_users (username, password_hash, created_at, updated_at)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (username, generate_password_hash(password), now_str(), now_str()),
                    )
                except pymysql.err.IntegrityError:
                    error = f"Username '{username}' already exists"
                else:
                    add_activity_log(
                        session["user"],
                        "Add Admin",
                        username,
                        f"Created admin account: {username}",
                    )
                    message = f"Admin '{username}' added successfully"
        elif action == "delete-admin":
            username = (request.form.get("username") or "").strip()

            if not username:
                error = "Admin username is required"
            elif username == "admin01":
                error = "The main admin account cannot be deleted"
            elif not query(
                "SELECT id FROM admin_users WHERE username=%s",
                (username,),
                one=True,
            ):
                error = "Admin account was not found"
            else:
                execute("DELETE FROM admin_users WHERE username=%s", (username,))
                add_activity_log(
                    session["user"],
                    "Delete Admin",
                    username,
                    f"Deleted admin account: {username}",
                )
                message = f"Admin '{username}' deleted successfully"

    admins = query(
        "SELECT username, created_at, updated_at FROM admin_users ORDER BY username"
    )
    return render_template(
        "admin_manage.html",
        admins=admins,
        message=message,
        error=error,
        reset_target=reset_target,
    )


@app.route("/api/devices", methods=["GET", "POST"])
def api_devices():
    if request.method == "GET":
        rows = query("SELECT * FROM devices ORDER BY name")
        return jsonify(jsonable(rows))

    if request.method == "POST":
        data = request.json
        parent_id = data.get('parentId')
        if parent_id == "": parent_id = None

        execute("""
            INSERT INTO devices (`name`, `ip_address`, `type`, `category`, `location`, `status`, `last_updated`, `parent_id`)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data['name'], data['ipAddress'], data['type'], data.get('category', 'Network'),
            data.get('location', 'Server Room'), data.get('status', 'Offline'), now_str(), parent_id
        ))
        add_activity_log(session.get("user", "admin"), "Add Device", data['name'], f"Added device: {data['name']}")
        return jsonify({"success": True})


@app.route("/api/devices/check-status", methods=["GET", "POST"])
def api_check_device_statuses():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify(jsonable(query("SELECT * FROM devices ORDER BY name")))


@app.route("/api/devices/<int:id>", methods=["PUT"])
def api_edit_device(id):
    data = request.json
    parent_id = data.get('parentId')
    if parent_id == "": parent_id = None

    if 'status' in data:
        execute("""
            UPDATE devices SET `name`=%s, `ip_address`=%s, `type`=%s, `category`=%s, `location`=%s,
                   `status`=%s, `last_updated`=%s, `parent_id`=%s WHERE id=%s
        """, (
            data['name'], data['ipAddress'], data['type'], data.get('category', 'Network'),
            data.get('location', 'Server Room'), data['status'], now_str(), parent_id, id
        ))
    else:
        execute("""
            UPDATE devices SET `name`=%s, `ip_address`=%s, `type`=%s, `category`=%s, `location`=%s,
                   `last_updated`=%s, `parent_id`=%s WHERE id=%s
        """, (
            data['name'], data['ipAddress'], data['type'], data.get('category', 'Network'),
            data.get('location', 'Server Room'), now_str(), parent_id, id
        ))
    add_activity_log(session.get("user", "admin"), "Edit Device", data['name'], f"Updated device: {data['name']}")
    return jsonify({"success": True})


@app.route("/api/devices/<int:id>", methods=["DELETE"])
def api_delete_device(id):
    dev = query("SELECT name FROM devices WHERE id=%s", (id,), one=True)
    dev_name = dev['name'] if dev else f"ID {id}"

    execute("UPDATE devices SET parent_id=NULL WHERE parent_id=%s", (id,))
    execute("DELETE FROM devices WHERE id=%s", (id,))

    add_activity_log(session.get("user", "admin"), "Delete Device", dev_name, f"Deleted device: {dev_name}")
    return jsonify({"success": True})


# === API Endpoint สำหรับอัปเดตสถานะจาก EVE-NG ===
@app.route("/api/devices/<int:id>/sync", methods=["POST"])
def api_sync_device(id):
    if "user" not in session: return jsonify({"error": "Unauthorized"}), 401

    dev = query("SELECT * FROM devices WHERE id=%s", (id,), one=True)
    if not dev:
        return jsonify({"error": "Device not found"}), 404

    ip_address = dev['ip_address']
    name = dev['name']

    # ดึงสถานะจาก EVE-NG
    status, output = fetch_status_from_eve(ip_address)

    # อัปเดตฐานข้อมูล
    execute("UPDATE devices SET status=%s, last_updated=%s WHERE id=%s", (status, now_str(), id))

    # บันทึกประวัติ
    add_activity_log(session.get("user", "admin"), "Sync Device", name, f"Synced status via EVE-NG: {status}")

    return jsonify({
        "success": True,
        "status": status,
        "output": output,
        "message": f"Successfully synced {name}"
    })


@app.route("/api/activity")
def api_get_activity():
    logs = query("SELECT * FROM activity_log ORDER BY id DESC LIMIT 50")
    return jsonify(jsonable(logs))


if __name__ == "__main__":
    # เตรียมตารางก่อนเริ่มเว็บ และเปิดตัวตรวจสถานะเป็น thread เบื้องหลัง
    init_db()
    threading.Thread(
        target=status_history_collector,
        daemon=True,
        name="device-status-history-collector",
    ).start()
    app.run(debug=True, port=5000, use_reloader=False)
