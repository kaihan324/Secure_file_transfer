import db.db as db

# بررسی نام کاربری و وجود در دیتابیس
def authenticate_user(username):
    user = db.get_user(username)
    return user is not None

# ثبت نام کاربر جدید
def register_user(username, public_key):
    if db.get_user(username):
        return False, "User already exists."
    db.add_user(username, public_key, role="guest")
    return True, "User registered successfully."

# دریافت نقش کاربر
def get_user_role(username):
    user = db.get_user(username)
    if user:
        return user[1]  # ایندکس 1 برای role است
    return None

# تغییر نقش کاربر (فقط توسط admin)
def change_user_role(username, new_role):
    db.update_role(username, new_role)
    return True, "User role updated."

# دریافت همه کاربران (برای مدیریت توسط admin)
def get_all_users():
    return db.get_all_users()

# بررسی مجوزها (RBAC)
def check_permission(username, action):
    """
    بررسی دسترسی کاربر به یک action خاص.
    """
    role = get_user_role(username)
    if role == "admin":
        return True  # admin همه دسترسی‌ها را دارد
    elif role == "maintainer":
        if action in ["upload_file", "download_file"]:
            return True
    elif role == "guest":
        if action == "download_file":
            return True
    return False

