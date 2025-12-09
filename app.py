from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import random

app = Flask(__name__)
app.secret_key = "supersecretkey123"

# ---------- Email Config ----------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'eshanthakur02@gmail.com'
app.config['MAIL_PASSWORD'] = 'xjyg gvoh kaph lzdj'

mail = Mail(app)

# ---------- Database Simulation ----------
users = {}           # {email: {"name": name, "password": hashed_pw, "verified": True/False}}
otp_storage = {}      # {email: otp}
node --version


# ---------- HOME ----------
@app.route('/')
def home():
    if 'user_email' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


# ---------- REGISTER ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm = request.form['confirm']

        if email in users:
            flash('⚠️ Email already registered! Please login.', 'warning')
            return redirect(url_for('login'))

        if password != confirm:
            flash('❌ Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        users[email] = {
            "name": name,
            "password": generate_password_hash(password),
            "verified": True
        }

        flash('✅ Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# ---------- LOGIN ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']

        user = users.get(email)
        if not user:
            flash('⚠️ No account found with this email.', 'warning')
            return redirect(url_for('login'))

        if not check_password_hash(user['password'], password):
            flash('❌ Incorrect password.', 'danger')
            return redirect(url_for('login'))

        # Generate and send OTP
        otp = str(random.randint(100000, 999999))
        otp_storage[email] = otp
        session['pending_email'] = email

        try:
            msg = Message("Your OTP Code 💌", sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f"Your OTP is {otp}. Valid for 10 minutes."
            mail.send(msg)
            flash('✅ OTP sent to your email! Check inbox or spam.', 'info')
        except Exception as e:
            print("Mail send failed:", e)
            flash('⚠️ Email not sent. Check mail configuration.', 'warning')

        return redirect(url_for('verify_otp'))

    return render_template('login.html')


# ---------- VERIFY OTP ----------
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    email = session.get('pending_email')
    if not email:
        flash('⚠️ Please login first.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp = request.form['otp']
        if otp_storage.get(email) == entered_otp:
            session['user_email'] = email
            session['user_name'] = users[email]['name']
            otp_storage.pop(email, None)
            session.pop('pending_email', None)
            flash('💖 Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('❌ Invalid OTP. Try again.', 'danger')
            return redirect(url_for('verify_otp'))

    return render_template('verify_otp.html', email=email)


# ---------- DASHBOARD ----------
@app.route('/dashboard')
def dashboard():
    email = session.get('user_email')  # ✅ Safe way to get session key
    
    if not email:
        flash('⚠️ Please log in first.', 'warning')
        return redirect(url_for('login'))

    user = users.get(email)
    if not user:
        flash('⚠️ User not found.', 'danger')
        return redirect(url_for('login'))

    return render_template('dashboard.html', name=user['name'])


# ---------- LOGOUT ----------
@app.route('/logout')
def logout():
    session.clear()
    flash('👋 Logged out successfully.', 'info')
    return redirect(url_for('login'))


# ---------- MAIN ----------
if __name__ == '__main__':
    app.run(debug=True, port=7711)
