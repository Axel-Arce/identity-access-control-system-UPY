PERMISSIONS = {
    "Admin":    {"view_stream", "view_all_cameras", "capture_snapshot", "update_camera_ip", "manage_users", "configure_system", "view_logs"},
    "Operator": {"view_stream", "view_all_cameras", "capture_snapshot", "update_camera_ip", "view_logs"},
    "Viewer":   {"view_stream", "update_camera_ip"},
}

MENU_OPTIONS = [
    ("1", "View my assigned camera stream",  "view_stream"),
    ("2", "View all available cameras",       "view_all_cameras"),
    ("3", "Capture snapshot",                 "capture_snapshot"),
    ("4", "Update my camera IP",              "update_camera_ip"),
    ("5", "View system logs",                 "view_logs"),
    ("6", "Manage users",                     "manage_users"),
    ("7", "Configure system",                 "configure_system"),
    ("0", "Exit",                             None),
]

def has_permission(user, action):
    #Returns True if the user's role allows the given action.
    return action in PERMISSIONS.get(user.get("role", ""), set())

def audit_log(user, action, granted):
    #Prints a structured audit entry for every access attempt.
    status = "GRANTED" if granted else "DENIED"
    print(f"[AUDIT] user='{user.get('email')}' | role='{user.get('role')}' | action='{action}' | status={status}")

def show_role_menu(user):
    #Displays a CLI menu filtered by the user's role permissions.
    print(f"\n=== MAIN MENU  [{user.get('role')}] — {user.get('name')} ===")

    visible = []
    for key, label, perm in MENU_OPTIONS:
        if perm is None or has_permission(user, perm):
            print(f"  {key}. {label}")
            visible.append((key, label, perm))

    return visible

if __name__ == "__main__":
    for role in ("Admin", "Operator", "Viewer"):
        fake_user = {"name": f"{role} User", "email": f"{role.lower()}@example.com", "role": role}
        show_role_menu(fake_user)
        print()
