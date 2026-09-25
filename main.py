import auth
import rbac
import camera
import database
import register_user
import update_user

def handle_view_stream(user):
    #Streams the camera assigned to the logged-in user.
    camera_ip = user.get("camera_ip")
    if not camera_ip:
        print("[ERROR] No camera IP assigned to your account.")
        return
    camera.stream_camera(camera_ip, window_title=f"Camera — {user['name']}")

def handle_view_all_cameras(user):
    #Lists every registered camera and lets the user pick one to stream.
    connection = database.get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT name, role, camera_ip FROM users ORDER BY role, name")
    rows = cursor.fetchall()
    connection.close()

    print("\n[INFO] Registered cameras:")
    for idx, (name, role, ip) in enumerate(rows, start=1):
        print(f"  {idx}. {name} [{role}] — {ip}")

    choice = input("\nEnter camera # to stream (or Enter to go back): ").strip()
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(rows):
            camera.stream_camera(rows[idx][2])
        else:
            print("[ERROR] Invalid camera number.")

def handle_snapshot(user):
    #Captures a snapshot from the user's assigned camera.
    camera_ip = user.get("camera_ip")
    if not camera_ip:
        print("[ERROR] No camera IP assigned to your account.")
        return
    output = input("Save snapshot as [snapshot.jpg]: ").strip() or "snapshot.jpg"
    camera.capture_snapshot(camera_ip, output)

def handle_update_camera_ip(user):
    #Lets the logged-in user update their own camera IP in the database.
    print(f"\n[INFO] Current camera IP: {user.get('camera_ip', 'none')}")
    new_ip = input("New camera IP: ").strip()

    if not new_ip:
        print("[ERROR] Camera IP cannot be empty.")
        return

    if database.update_user_camera_ip(user["email"], new_ip):
        user["camera_ip"] = new_ip
        print(f"[SUCCESS] Camera IP updated to '{new_ip}' for this session.")

def handle_view_logs(user):
    print("\n[LOGS] Audit log is printed to stdout during this session.")

def handle_manage_users(user):
    print("\n=== USER MANAGEMENT ===")
    print("  1. Register new user")
    print("  2. Update existing user")
    print("  3. List all users")

    choice = input("Option: ").strip()
    if choice == "1":
        register_user.register_prompt()
    elif choice == "2":
        update_user.update_prompt()
    elif choice == "3":
        database.fetch_all_users()
    else:
        print("[ERROR] Invalid option.")

def handle_configure(user):
    print("\n[CONFIG] Edit the '.env' file to change system settings.")

ACTION_HANDLERS = {
    "view_stream":      handle_view_stream,
    "view_all_cameras": handle_view_all_cameras,
    "capture_snapshot": handle_snapshot,
    "update_camera_ip": handle_update_camera_ip,
    "view_logs":        handle_view_logs,
    "manage_users":     handle_manage_users,
    "configure_system": handle_configure,
}

def run():
    print("\n=== IDENTITY AND ACCESS CONTROL MANAGEMENT SYSTEM ===")

    user = auth.login_prompt()
    if user is None:
        print("\n[SYSTEM] Access denied. Exiting.")
        return

    while True:
        menu_options = rbac.show_role_menu(user)
        choice = input("\nSelect an option: ").strip()

        selected = next((opt for opt in menu_options if opt[0] == choice), None)
        if selected is None:
            print("[ERROR] Invalid option.")
            continue

        _, label, action = selected

        if action is None:
            print("\n[INFO] Session closed. Goodbye!")
            break

        rbac.audit_log(user, action, granted=rbac.has_permission(user, action))

        handler = ACTION_HANDLERS.get(action)
        if handler:
            handler(user)

if __name__ == "__main__":
    run()
