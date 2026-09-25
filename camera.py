import os

import cv2
from dotenv import load_dotenv

load_dotenv()

RTSP_PORT = os.getenv("CAMERA_RTSP_PORT", "554")
RTSP_PATH = os.getenv("CAMERA_RTSP_PATH", "/stream")

def build_rtsp_url(camera_ip):
    #Builds an RTSP URL from a stored camera_ip value.
    if camera_ip.startswith(("rtsp://", "http://")):
        return camera_ip
    host, port = (camera_ip.rsplit(":", 1) if ":" in camera_ip else (camera_ip, RTSP_PORT))
    return f"rtsp://{host}:{port}{RTSP_PATH}"

def stream_camera(camera_ip, window_title="Camera Stream"):
    #Opens a live RTSP stream in an OpenCV window. Press 'q' to quit.
    url = build_rtsp_url(camera_ip)
    print(f"\n[CAMERA] Connecting to: {url}")

    cap = cv2.VideoCapture(url)
    if not cap.isOpened():
        print(f"[ERROR] Could not open stream at '{camera_ip}'.")
        return False

    print("[INFO] Stream opened. Press 'q' to close.")

    while True:
        ret, frame = cap.read()
        if not ret:
            print("[WARN] Stream interrupted.")
            break

        cv2.imshow(window_title, frame)
        if cv2.waitKey(1) & 0xFF == ord("q"):
            print("[INFO] Stream closed by user.")
            break

    cap.release()
    cv2.destroyAllWindows()
    return True

def capture_snapshot(camera_ip, output_path="snapshot.jpg"):
    #Captures a single frame from the camera and saves it as JPEG.
    url = build_rtsp_url(camera_ip)
    print(f"\n[CAMERA] Capturing snapshot from: {url}")

    cap = cv2.VideoCapture(url)
    if not cap.isOpened():
        print(f"[ERROR] Could not connect to camera at '{camera_ip}'.")
        return False

    ret, frame = cap.read()
    cap.release()

    if not ret:
        print("[ERROR] Failed to capture frame.")
        return False

    cv2.imwrite(output_path, frame)
    print(f"[SUCCESS] Snapshot saved to '{output_path}'.")
    return True

if __name__ == "__main__":
    print("=== MODULE 7: IP CAMERA ===")
    print("  1. Open live stream")
    print("  2. Capture snapshot")

    choice = input("\nOption: ").strip()
    ip = input("Camera IP: ").strip()

    if choice == "1":
        stream_camera(ip)
    elif choice == "2":
        out = input("Output file [snapshot.jpg]: ").strip() or "snapshot.jpg"
        capture_snapshot(ip, out)
    else:
        print("[ERROR] Invalid option.")
