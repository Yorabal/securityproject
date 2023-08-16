from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
from cryptography.fernet import Fernet
import time
import os
from dotenv import load_dotenv
from password_strength import PasswordPolicy
from password_strength import PasswordStats
import pyotp
from pyotp import TOTP
import requests
from datetime import timedelta, datetime
from flask_session import Session
import redis
from flask_bcrypt import Bcrypt
import hashlib
import secrets
import smtplib
from flask_cors import cross_origin
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

message = """"From: sandromneojunjie@gmail.com
Subject: OTP

YOUR OTP MESSAGE
"""

bcrypt = Bcrypt()
load_dotenv()
key = pyotp.random_base32()
totp = TOTP(key, interval=120)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_USE_SIGNER'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=1)
app.config['SESSION_REDIS'] = redis.from_url(os.getenv('REDIS_URL'))
Session(app)

app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['MYSQL_PORT'] = int(os.getenv('MYSQL_PORT'))
recaptcha_secret_key = os.getenv('RECAPTCHA_SECRET_KEY')
email_username = os.getenv('EMAIL_USERNAME')
email_password = os.getenv('EMAIL_PASSWORD')

mysql = MySQL(app)

policy = PasswordPolicy.from_names(
    length=6,  # min length: 6
    uppercase=1,  # need min. 1 uppercase letters
    numbers=1,  # need min. 1 digits
    special=1,
    strength=0.10  # need a password that scores at least 0.5 with its entropy bits
)

# Maximum number of allowed login attempts
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_DURATION = 300  # 5 minutes in seconds


@app.before_request
def check_otp_verification():
    if request.endpoint not in ['static', 'verify_otp', 'home']:
        if 'loggedin' in session and 'otp_verified' in session and not session['otp_verified']:
            return redirect(url_for('verify_otp'))


# Before request: Check and unlock locked accounts
@app.before_request
def check_account_lock():
    if 'login_attempts' in session:
        for username, attempt_data in session['login_attempts'].items():
            if attempt_data['locked']:
                if (time.time() - attempt_data['lockout_time']) > LOCKOUT_DURATION:
                    session['login_attempts'][username]['attempts'] = 0
                    session['login_attempts'][username]['locked'] = False
                    session.modified = True


def generate_secure_token():
    salt = secrets.token_hex(16)
    token = hashlib.sha256(salt.encode()).hexdigest()
    return token


def hashed_reset_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


@app.route('/', methods=['GET', 'POST'])
def login():
    # Output message if something goes wrong...
    msg = ''
    recaptcha_site_key = os.getenv('RECAPTCHA_SITE_KEY')

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        try:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
            account = cursor.fetchone()
            session.permanent = True

            if account:
                if 'login_attempts' not in session:
                    session['login_attempts'] = {}

                if account['username'] not in session['login_attempts']:
                    session['login_attempts'][account['username']] = {'attempts': 0, 'locked': False}

                if session['login_attempts'][account['username']]['locked']:
                    if (time.time() - session['login_attempts'][account['username']]['lockout_time']) > LOCKOUT_DURATION:
                        session['login_attempts'][account['username']]['attempts'] = 0
                        session['login_attempts'][account['username']]['locked'] = False
                    else:
                        msg = f"Logging in locked due to multiple failed login attempts. Please try again later."
                        return render_template('index.html', msg=msg)

                if bcrypt.check_password_hash(account['password'], password):
                    recaptcha_response = request.form.get('g-recaptcha-response')
                    recaptcha_secret = os.getenv('RECAPTCHA_SECRET_KEY')

                    recaptcha_data = {
                        'secret': recaptcha_secret,
                        'response': recaptcha_response
                    }

                    recaptcha_verification = requests.post('https://www.google.com/recaptcha/api/siteverify',
                                                           data=recaptcha_data)
                    recaptcha_result = recaptcha_verification.json()

                    if recaptcha_result['success']:
                        session['loggedin'] = True
                        session['id'] = account['id']
                        session['username'] = account['username']
                        session['login_attempts'][account['username']]['attempts'] = 0
                        session['login_attempts'][account['username']]['locked'] = False

                        # Generate and send OTP only when user successfully logs in and CAPTCHA is verified
                        if 'otp_sent' not in session or not session['otp_sent']:
                            totp_key = pyotp.random_base32()
                            session['totp_key'] = totp_key
                            totp = TOTP(totp_key, interval=120)
                            one_time_password = totp.now()

                            # Send OTP
                            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                            cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
                            account = cursor.fetchone()

                            with open('symmetric.key', 'rb') as key_file:
                             key = key_file.read()

                            f = Fernet(key)
                            decrypted_email = f.decrypt(account['email']).decode()

                            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                                server.login(email_username, email_password)
                                server.sendmail(
                                    os.getenv('EMAIL_USERNAME'),
                                    [decrypted_email],
                                    message + one_time_password
                                )
                            session['otp_sent'] = True

                        return redirect(url_for('verify_otp'))
                    else:
                        msg = 'reCAPTCHA verification failed. Please prove that you are human!'
                else:
                    session['login_attempts'][account['username']]['attempts'] += 1
                    if session['login_attempts'][account['username']]['attempts'] >= MAX_LOGIN_ATTEMPTS:
                        session['login_attempts'][account['username']]['locked'] = True
                        session['login_attempts'][account['username']]['lockout_time'] = time.time()
                    msg = 'Incorrect username/password!'
            else:
                msg = 'Account doesn’t exist or username/password incorrect!'
        except Exception as e:
            msg = 'An error occurred: {}'.format(str(e))

    return render_template('index.html', msg=msg, recaptcha_site_key=recaptcha_site_key)


@app.route('/MyWebApp/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'loggedin' in session and session['loggedin']:
        # Use the existing key stored in the session
        if 'totp_key' not in session:
            session['totp_key'] = pyotp.random_base32()

        totp = TOTP(session['totp_key'], interval=120)
        one_time_password = totp.now()
        if request.method == 'POST':
            input_otp = request.form.get('otp')
            if totp.verify(input_otp):
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
                account = cursor.fetchone()

                session['otp_verified'] = True
                session['login_attempts'].pop(account['username'], None)
                session.pop('lockout_time', None)
                return redirect(url_for('home'))
            else:
                msg = "Invalid OTP. Please try again."
                return render_template('verify_otp.html', msg=msg, generated_otp=one_time_password)

        else:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
            account = cursor.fetchone()

            # Decrypt the email address before sending the email
            with open('symmetric.key', 'rb') as key_file:
                key = key_file.read()

            f = Fernet(key)
            decrypted_email = f.decrypt(account['email']).decode()

            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(email_username, email_password)
                server.sendmail(
                    os.getenv('EMAIL_USERNAME'),
                    [decrypted_email],
                    message + one_time_password
                )

            return render_template('verify_otp.html', msg='', generated_otp=one_time_password)

    return redirect(url_for('login'))


# Function to send email
def send_email(to_email, subject, body):
    from_email = os.getenv('EMAIL_USERNAME')
    password = os.getenv('EMAIL_PASSWORD')

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())


@app.route('/MyWebApp/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/MyWebApp/register', methods=['GET', 'POST'])
def register():
    msg = ''
    recaptcha_site_key = os.getenv('RECAPTCHA_SITE_KEY')

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        email = request.form.get('email')

        stats = PasswordStats(password)
        check_policy = policy.test(password)

        if password != confirm_password:
            msg = "Passwords do not match."
        elif stats.strength() < 0.10 or len(check_policy) > 0:
            msg = "Password not strong enough or does not meet password criteria. Avoid consecutive characters and easily guessed words."
        else:
            recaptcha_response = request.form.get('g-recaptcha-response')
            recaptcha_secret = os.getenv('RECAPTCHA_SECRET_KEY')

            recaptcha_data = {
                'secret': recaptcha_secret,
                'response': recaptcha_response
            }

            recaptcha_verification = requests.post('https://www.google.com/recaptcha/api/siteverify',
                                                   data=recaptcha_data)
            recaptcha_result = recaptcha_verification.json()

            if not recaptcha_result['success']:
                msg = 'reCAPTCHA verification failed. Please prove that you are human!'
            else:
                try:
                    # Rest of your registration logic here
                    login_attempt = 0
                    email = email.encode()
                    hashpwd = bcrypt.generate_password_hash(password)

                    key = Fernet.generate_key()
                    with open("symmetric.key", "wb") as fo:
                        fo.write(key)

                    f = Fernet(key)
                    encrypted_email = f.encrypt(email)

                    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                    cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
                    existingInfo = cursor.fetchone()
                    if existingInfo is not None:
                        msg = "This account already exists! Try logging in instead."
                    else:
                        cursor.execute(
                            'INSERT INTO accounts (username, password, email, login_attempts) VALUES (%s, %s, %s, %s)',
                            (username, hashpwd, encrypted_email, login_attempt))
                        mysql.connection.commit()
                        msg = 'You have successfully registered!'
                except Exception as e:
                    msg = 'An error occurred: {}'.format(str(e))

    return render_template('register.html', msg=msg, recaptcha_site_key=recaptcha_site_key)


@app.route('/MyWebApp/home')
def home():
    if 'loggedin' in session and 'otp_verified' in session and session['otp_verified']:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('verify_otp'))


@app.route('/MyWebApp/reauthenticate', methods=['GET', 'POST'])
def reauthenticate():
    msg = ''

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        try:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
            account = cursor.fetchone()

            if account and bcrypt.check_password_hash(account['password'], password):
                session['reauthenticated'] = True
                return redirect(url_for('profile'))
            else:
                msg = 'Invalid username/password!'
        except Exception as e:
            msg = 'An error occurred: {}'.format(str(e))

    return render_template('reauthenticate.html', msg=msg)


@app.route('/MyWebApp/profile')
def profile():
    if 'loggedin' in session and 'reauthenticated' in session and session['reauthenticated']:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()

        encrypted_email = account['email'].encode()

        with open('symmetric.key', 'rb') as key_file:
            key = key_file.read()

        try:
            f = Fernet(key)

            decrypted_email = f.decrypt(encrypted_email)

            masked_email = mask_email(decrypted_email.decode())

            return render_template('profile.html', account=account, email=masked_email)
        except Exception as e:
            print("Decryption Error:", e)
            email = "Decryption Error"

        return render_template('profile.html', account=account, email=email)

    return redirect(url_for('reauthenticate'))


def mask_email(email):
    parts = email.split('@')
    if len(parts) == 2:
        username, domain = parts
        masked_username = username[0] + '*' * (len(username) - 1)
        masked_email = masked_username + '@' + domain
        return masked_email
    return email


@app.route('/<path:invalid_path>')
def error_404(invalid_path):
    return render_template('error.html', title='404 Not Found',
                           message=f'The requested URL "{invalid_path}" was not found.'), 404


@app.route('/simulate_500')
def simulate_500():
    # Simulate an error by raising an exception
    raise Exception("This is a simulated 500 error")


@app.errorhandler(500)
def internal_server_error(error):
    return render_template('error.html', title='500 Internal Server Error',
                           message='An internal server error occurred. Please try again later.'), 500


@app.route('/MyWebApp/reset_password', methods=['GET', 'POST'])
def reset_password():
    msg = ''

    if request.method == 'POST' and 'username' in request.form:
        username = request.form['username']

        try:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
            account = cursor.fetchone()

            if account:
                # Generate a reset token and send reset email
                reset_token = generate_secure_token()
                hashed_token = hashed_reset_token(reset_token)

                # Store the hashed reset token and expiration timestamp in the reset_tokens table
                expiration_timestamp = datetime.utcnow() + timedelta(
                    hours=1)  # Set an expiration time (e.g., 1 hour from now)

                cursor.execute(
                    'INSERT INTO reset_tokens (username, token_hash, expiration_timestamp) VALUES (%s, %s, %s)',
                    (username, hashed_token, expiration_timestamp))
                mysql.connection.commit()

                # Decrypt the email address before sending the email
                with open('symmetric.key', 'rb') as key_file:
                    key = key_file.read()

                f = Fernet(key)
                decrypted_email = f.decrypt(account['email']).decode()

                # Construct the reset password token link manually
                reset_link = f"http://http://127.0.0.1:5000/MyWebApp/reset_password_token/{reset_token}"

                # Send the reset email
                subject = "Password Reset Request"
                body = f"Click the following link to reset your password: {reset_link}"
                send_email(decrypted_email, subject, body)

                msg = "A password reset link has been sent to your email."

            else:
                msg = 'Account not found.'
        except Exception as e:
            msg = 'An error occurred: {}'.format(str(e))

    return render_template('reset_password.html', msg=msg)


@app.route('/MyWebApp/reset_password_token/<token>', methods=['GET', 'POST'])
@cross_origin()
def reset_password_token(token):
    msg = ''

    if request.method == 'POST' and 'password' in request.form and 'confirm_password' in request.form:
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validate password against policy
        check_policy = policy.test(password)
        if password != confirm_password:
            msg = "Passwords do not match."
        elif len(check_policy) > 0:
            msg = "Password does not meet password criteria. Avoid consecutive characters and easily guessed words."
        else:
            try:
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('SELECT * FROM reset_tokens WHERE token_hash = %s',
                               (hashlib.sha256(token.encode()).hexdigest(),))
                token_info = cursor.fetchone()

                if token_info:
                    # Check if the new password is the same as the last password
                    cursor.execute('SELECT * FROM accounts WHERE username = %s', (token_info['username'],))
                    account = cursor.fetchone()
                    if account and bcrypt.check_password_hash(account['password'], password):
                        msg = "Your new password cannot be the same as your last password."
                    else:
                        # Update the password and unlock the account
                        new_hashpwd = bcrypt.generate_password_hash(password)
                        cursor.execute('UPDATE accounts SET password = %s, locked = 0 WHERE username = %s',
                                       (new_hashpwd, token_info['username']))
                        mysql.connection.commit()

                        # Delete the used reset token
                        cursor.execute('DELETE FROM reset_tokens WHERE token_hash = %s', (hashed_reset_token(token),))

                        # Unlock the account in session data
                        if 'login_attempts' in session and token_info['username'] in session['login_attempts']:
                            session['login_attempts'][token_info['username']]['locked'] = False

                        msg = "Your password has been successfully reset. You can now log in with the new password. Your account has also been unlocked."
                else:
                    msg = 'Invalid or expired reset token.'
            except Exception as e:
                msg = 'An error occurred: {}'.format(str(e))

    return render_template('reset_password_token.html', msg=msg, token=token)


if __name__ == '__main__':
    app.run()
