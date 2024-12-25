import smtplib
from email.mime.text import MIMEText

def send_email_notification(subject, body, to_email):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = 'your_email@example.com'
    msg['To'] = to_email

    try:
        with smtplib.SMTP('smtp.example.com') as server:
            server.login('your_email@example.com', 'password')
            server.sendmail('your_email@example.com', to_email, msg.as_string())
    except smtplib.SMTPException as e:
        print(f"SMTP error: {e}")

def notify_user(message):
    print(f"Notification: {message}") 