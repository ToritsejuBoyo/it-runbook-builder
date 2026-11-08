#!/usr/bin/env python3
"""
Media Generation Engine: it-runbook-builder

Generates:
- assets/demo.mp4: High-definition 1080p terminal demonstration video
- assets/demo.gif: Animated 4-fps terminal walkthrough for GitHub README playback

Strictly adheres to Workspace Rule 7 (Zero-Emoji Enterprise Tone) and
Rule 10 (Rich Media & Installation Guide).
"""

import os
from pathlib import Path
import subprocess
from PIL import Image, ImageDraw, ImageFont

WIDTH = 1200
HEIGHT = 720
BG_COLOR = (15, 23, 42)       # Slate navy #0F172A
HEADER_BG = (30, 41, 59)
TEXT_COLOR = (241, 245, 249)
MUTED_TEXT = (148, 163, 184)
PROMPT_COLOR = (56, 189, 248)  # Cyan #38BDF8
CMD_COLOR = (255, 255, 255)
GREEN_COLOR = (52, 211, 153)
YELLOW_COLOR = (251, 191, 36)
RED_COLOR = (248, 113, 113)
BLUE_COLOR = (96, 165, 250)
CYAN_COLOR = (56, 189, 248)


def create_base_canvas():
    img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Window top bar
    draw.rectangle([(0, 0), (WIDTH, 42)], fill=HEADER_BG)
    draw.ellipse([(16, 14), (28, 26)], fill=(239, 68, 68))
    draw.ellipse([(36, 14), (48, 26)], fill=(245, 158, 11))
    draw.ellipse([(56, 14), (68, 26)], fill=(16, 185, 129))

    try:
        font = ImageFont.truetype("arial.ttf", 14)
    except Exception:
        font = ImageFont.load_default()
    draw.text(
        (WIDTH // 2 - 220, 12),
        "terminal - it-runbook-builder (Automated IT Runbook & SOP Engine)",
        font=font,
        fill=MUTED_TEXT,
    )

    return img, draw


def render_frames(output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        font = ImageFont.truetype("consola.ttf", 14)
        bold_font = ImageFont.truetype("consolab.ttf", 14)
        title_font = ImageFont.truetype("consolab.ttf", 16)
    except Exception:
        font = ImageFont.load_default()
        bold_font = font
        title_font = font

    prompt = "admin@ops-bastion:~$ "
    cmd = "python scripts/runbook_builder.py -i tests/fixtures/fixture-bash-ssl-renewal.txt --format markdown --sanitize"

    screens = [
        # Frame 1: Empty prompt
        [
            (30, 65, prompt, PROMPT_COLOR, bold_font),
            (210, 65, "", CMD_COLOR, bold_font),
        ],
        # Frame 2: Command typed
        [
            (30, 65, prompt, PROMPT_COLOR, bold_font),
            (210, 65, cmd, CMD_COLOR, bold_font),
        ],
        # Frame 3: Processing & telemetry analysis
        [
            (30, 65, prompt, PROMPT_COLOR, bold_font),
            (210, 65, cmd, CMD_COLOR, bold_font),
            (30, 95, "[*] Ingesting raw terminal telemetry: tests/fixtures/fixture-bash-ssl-renewal.txt", BLUE_COLOR, font),
            (30, 115, "[+] Filtered 3 noise commands (cd, ls, whoami)", GREEN_COLOR, font),
            (30, 135, "[+] Applied client-side sanitization: Masked 2 internal IP addresses and corporate domains", GREEN_COLOR, font),
            (30, 155, "[+] Synthesized 5 execution steps with paired verification checks", GREEN_COLOR, font),
            (30, 175, "[+] Derived automated rollback and backout plan", GREEN_COLOR, font),
            (30, 200, "================================================================================", MUTED_TEXT, font),
            (30, 220, "STANDARD OPERATING PROCEDURE: TLS/SSL CERTIFICATE RENEWAL", CYAN_COLOR, title_font),
            (30, 245, "================================================================================", MUTED_TEXT, font),
        ],
        # Frame 4: Runbook preview (Metadata + Pre-checks + Steps)
        [
            (30, 65, prompt, PROMPT_COLOR, bold_font),
            (210, 65, cmd, CMD_COLOR, bold_font),
            (30, 95, "[+] Applied client-side sanitization: Masked 2 internal IP addresses and corporate domains", GREEN_COLOR, font),
            (30, 120, "================================================================================", MUTED_TEXT, font),
            (30, 140, "STANDARD OPERATING PROCEDURE: TLS/SSL CERTIFICATE RENEWAL", CYAN_COLOR, title_font),
            (30, 165, "================================================================================", MUTED_TEXT, font),
            (30, 185, "Document ID: SOP-20261108-A4F1 | Owner: Systems Engineering / DevOps | Target: Production Linux", TEXT_COLOR, font),
            (30, 210, "1. PREREQUISITES & ACCESS REQUIREMENTS:", YELLOW_COLOR, bold_font),
            (30, 230, "   - [x] Standard operational change window or emergency authorization.", TEXT_COLOR, font),
            (30, 250, "   - [x] Elevated administrative privileges (sudo or root access on target host).", TEXT_COLOR, font),
            (30, 275, "2. PRE-FLIGHT ASSERTION CHECKS:", YELLOW_COLOR, bold_font),
            (30, 295, "   - Step 4.1: Verify certificate expiration dates before mutating state", TEXT_COLOR, font),
            (30, 315, "     Command: openssl x509 -in /etc/ssl/certs/api-gateway.crt -noout -dates", CYAN_COLOR, font),
            (30, 340, "3. STEP-BY-STEP EXECUTION PROCEDURE:", BLUE_COLOR, bold_font),
            (30, 360, "   - Step 5.1: Stage configuration / file backup: cp /etc/ssl/certs/api-gateway.crt.bak", TEXT_COLOR, font),
            (30, 380, "   - Step 5.2: Execute Certbot renewal: certbot certonly --standalone -d <TARGET_FQDN>", TEXT_COLOR, font),
            (30, 400, "   - Step 5.3: Validate Nginx syntax before reload: nginx -t", GREEN_COLOR, font),
            (30, 420, "   - Step 5.4: Reload web service: systemctl reload nginx", TEXT_COLOR, font),
        ],
        # Frame 5: Verification & Rollback
        [
            (30, 65, prompt, PROMPT_COLOR, bold_font),
            (210, 65, cmd, CMD_COLOR, bold_font),
            (30, 95, "3. STEP-BY-STEP EXECUTION PROCEDURE:", BLUE_COLOR, bold_font),
            (30, 115, "   - Step 5.3: Validate Nginx syntax before reload: nginx -t", GREEN_COLOR, font),
            (30, 135, "   - Step 5.4: Reload web service: systemctl reload nginx", TEXT_COLOR, font),
            (30, 160, "4. POST-EXECUTION VERIFICATION & HEALTH CHECKS:", GREEN_COLOR, bold_font),
            (30, 180, "   - Verification 6.1: Confirm active service status: systemctl is-active nginx", TEXT_COLOR, font),
            (30, 200, "   - Verification 6.2: Probe HTTPS health endpoint: curl -I https://<TARGET_FQDN>/healthz", TEXT_COLOR, font),
            (30, 220, "   - Verification 6.3: Inspect live TLS handshake: openssl s_client -connect <TARGET_IP>:443", TEXT_COLOR, font),
            (30, 250, "5. MANDATORY ROLLBACK & BACKOUT PLAN:", RED_COLOR, bold_font),
            (30, 270, "   - Reversal 7.1: Restore previous certificate backup: cp api-gateway.crt.bak api-gateway.crt", TEXT_COLOR, font),
            (30, 290, "   - Reversal 7.2: Revert private key backup: cp api-gateway.key.bak api-gateway.key", TEXT_COLOR, font),
            (30, 310, "   - Reversal 7.3: Reload web service to restore previous TLS state: systemctl reload nginx", TEXT_COLOR, font),
            (30, 340, "6. TROUBLESHOOTING & COMMON FAILURE MODES:", YELLOW_COLOR, bold_font),
            (30, 360, "   - Symptom: Port 80 binding conflict during standalone challenge", TEXT_COLOR, font),
            (30, 380, "     Remediation: Inspect listeners: ss -tlpn | grep ':80' or switch to webroot mode.", MUTED_TEXT, font),
            (30, 410, "[+] IT Runbook successfully generated (Exported to Markdown, Confluence, and HTML)", GREEN_COLOR, bold_font),
            (30, 440, prompt, PROMPT_COLOR, bold_font),
        ]
    ]

    durations = [3, 4, 6, 9, 12]
    frame_idx = 0

    for screen_idx, elements in enumerate(screens):
        count = durations[screen_idx]
        for _ in range(count):
            img, draw = create_base_canvas()
            for elem in elements:
                x, y, text, color, f = elem
                draw.text((x, y), text, font=f, fill=color)
            out_file = output_dir / f"frame_{frame_idx:04d}.png"
            img.save(out_file)
            frame_idx += 1

    return frame_idx


def generate_mp4(frames_dir: Path, output_mp4: Path):
    cmd = [
        "ffmpeg", "-y",
        "-framerate", "4",
        "-i", str(frames_dir / "frame_%04d.png"),
        "-c:v", "libx264",
        "-profile:v", "high",
        "-crf", "18",
        "-pix_fmt", "yuv420p",
        str(output_mp4)
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def generate_gif(frames_dir: Path, output_gif: Path):
    palette_path = frames_dir / "palette.png"
    cmd_palette = [
        "ffmpeg", "-y",
        "-framerate", "4",
        "-i", str(frames_dir / "frame_%04d.png"),
        "-vf", "fps=4,scale=1200:-1:flags=lanczos,palettegen=stats_mode=diff",
        str(palette_path)
    ]
    subprocess.run(cmd_palette, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    cmd_gif = [
        "ffmpeg", "-y",
        "-framerate", "4",
        "-i", str(frames_dir / "frame_%04d.png"),
        "-i", str(palette_path),
        "-lavfi", "fps=4,scale=1200:-1:flags=lanczos [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=3",
        str(output_gif)
    ]
    subprocess.run(cmd_gif, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def main():
    repo_root = Path(__file__).resolve().parent.parent
    assets_dir = repo_root / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    frames_dir = assets_dir / "frames"

    print("[*] Rendering terminal demo animation frames...")
    total_frames = render_frames(frames_dir)
    print(f"[+] Rendered {total_frames} frames.")

    mp4_path = assets_dir / "demo.mp4"
    gif_path = assets_dir / "demo.gif"

    print("[*] Compiling HD video (assets/demo.mp4)...")
    generate_mp4(frames_dir, mp4_path)
    print(f"[+] Generated: {mp4_path} ({mp4_path.stat().st_size / 1024:.1f} KB)")

    print("[*] Compiling animated GIF (assets/demo.gif)...")
    generate_gif(frames_dir, gif_path)
    print(f"[+] Generated: {gif_path} ({gif_path.stat().st_size / 1024:.1f} KB)")

    # Clean up intermediate frames
    for f in frames_dir.glob("*.png"):
        f.unlink()
    frames_dir.rmdir()
    print("[+] Cleaned up temporary rendering frames.")


if __name__ == "__main__":
    main()
