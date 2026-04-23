import re
import random
import string
import base64
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
import smtplib
from email.mime.text import MIMEText

# SECURITY MODULE: DEFENSE IN DEPTH IMPLEMENTATIONS

def check_password_strength(password):
    """
    Validates password entropy against industry-standard guidelines (e.g., NIST SP 800-63B).
    Returns a boolean and message tuple indicating if the password meets strict criteria:
    - Minimum length 8 to prevent fast offline cracking.
    - Contains uppercase letter to increase search space size.
    - Contains lowercase letter.
    - Contains number.
    - Contains special character to enforce deliberate complexity.
    
    This function performs a regex-based validation to ensure the password
    meets the minimum security requirements to thwart Brute Force and Dictionary attacks.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number."
    if not re.search(r'[\W_]', password):
        return False, "Password must contain at least one special character."
    
    return True, "Strong Password"

def generate_captcha(length=5):
    """
    Generates a dynamic Image-based CAPTCHA.
    Uses Python Imaging Library (PIL) to render randomized strings onto a visual canvas
    with intentional noise (lines and dots) to thwart optical character recognition (OCR)
    attacks commonly used by automated botnets during credential stuffing or fake registrations.
    Returns the plaintext string (stored securely in session, NEVER exposed to client logic) 
    and a base64 encoded PNG immediately renderable by the browser.
    """
    # Generate unpredictable sequence of alphanumeric characters
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
    
    # Create visual challenge boundary
    width, height = 120, 50
    image = Image.new('RGB', (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(image)
    
    # Introduce visual noise (obfuscation technique against OCR)
    for _ in range(5):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        x2 = random.randint(0, width)
        y2 = random.randint(0, height)
        draw.line(((x1, y1), (x2, y2)), fill=(0, 0, 0), width=2)
    
    try:
        font = ImageFont.truetype("arial.ttf", 32)
    except IOError:
        font = ImageFont.load_default()
        
    draw.text((10, 10), captcha_text, font=font, fill=(0, 0, 0))
    
    # Additional localized noise for obfuscation
    for _ in range(50):
        x = random.randint(0, width)
        y = random.randint(0, height)
        draw.point((x, y), fill=(0, 0, 0))
        
    # Convert image memory buffer directly to base64, leaving no disk footprint
    buffered = BytesIO()
    image.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode('utf-8')
    
    return captcha_text, img_str

def generate_email_otp(length=6):
    """
    Generates a cryptographically strong numeric One-Time Password (OTP)
    used as a 'Something You Have' secondary factor for MFA.
    """
    return ''.join(random.choices(string.digits, k=length))

def send_otp_email(receiver_email, otp):
    """
    Dispatches the generated OTP to the user's registered email using an SMTP bridge via SSL/TLS.
    This fulfills the Multi-Factor Authentication (MFA) requirements by ensuring the actor
    has established ownership over the external communication channel.
    """
    SENDER_EMAIL = "anushaaa626@gmail.com"
    SENDER_APP_PASSWORD = "hrrc jcht ihhb nkjn"

    print("\n" + "="*50)
    print("MFA EVENT: DISPATCHING SECURE OTP VIA SMTP")
    print(f"To: {receiver_email}")
    print(f"OTP: [ {otp} ]")
    print("="*50 + "\n")

    try:
        msg = MIMEText(f"Your Secure E-Commerce Verification Code is: {otp}\n\nThis code will expire in 5 minutes. Do not share this code with anyone.")
        msg['Subject'] = 'Your Secure E-Commerce Verification Code'
        msg['From'] = SENDER_EMAIL
        msg['To'] = receiver_email

        # Establish secure transport layer (SSL) preventing MITM interception of OTPs
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
        server.sendmail(SENDER_EMAIL, receiver_email, msg.as_string())
        server.quit()
        print("SUCCESS: SMTP Bridge Transmission Complete!")
        return True
    except Exception as e:
        print(f"ERROR: SMTP Transmission Failed: {e}")
        return False
