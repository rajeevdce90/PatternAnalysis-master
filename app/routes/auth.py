from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app.models.user import User
from app import db, bcrypt
from datetime import datetime
import pyotp

bp = Blueprint('auth', __name__)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if user.two_factor_enabled:
                # Store user ID in session and redirect to 2FA verification
                session['_2fa_user_id'] = user.id
                return redirect(url_for('auth.verify_2fa'))
            
            # Log successful login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            login_user(user, remember=remember)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.index'))
        
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@bp.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if '_2fa_user_id' not in session:
        return redirect(url_for('auth.login'))
    
    user = User.query.get(session['_2fa_user_id'])
    if not user:
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        code = request.form.get('code')
        totp = pyotp.TOTP(user.two_factor_secret)
        
        if totp.verify(code):
            # Log successful login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            login_user(user)
            session.pop('_2fa_user_id', None)
            return redirect(url_for('main.index'))
        
        flash('Invalid 2FA code', 'danger')
    return render_template('verify_2fa.html')

@bp.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if current_user.two_factor_enabled:
        flash('2FA is already enabled', 'info')
        return redirect(url_for('main.profile'))
    
    if not current_user.two_factor_secret:
        current_user.two_factor_secret = pyotp.random_base32()
        db.session.commit()
    
    totp = pyotp.TOTP(current_user.two_factor_secret)
    provisioning_uri = totp.provisioning_uri(
        current_user.email,
        issuer_name="Pattern Analysis"
    )
    
    if request.method == 'POST':
        code = request.form.get('code')
        if totp.verify(code):
            current_user.two_factor_enabled = True
            db.session.commit()
            flash('2FA has been enabled', 'success')
            return redirect(url_for('main.profile'))
        flash('Invalid code', 'danger')
    
    return render_template('setup_2fa.html', secret=current_user.two_factor_secret,
                         provisioning_uri=provisioning_uri)

@bp.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    if not current_user.two_factor_enabled:
        flash('2FA is not enabled', 'info')
        return redirect(url_for('main.profile'))
    
    current_user.two_factor_enabled = False
    current_user.two_factor_secret = None
    db.session.commit()
    
    flash('2FA has been disabled', 'success')
    return redirect(url_for('main.profile'))

@bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    user = User.verify_reset_password_token(token)
    if not user:
        flash('Invalid or expired reset token', 'danger')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        user.set_password(password)
        db.session.commit()
        flash('Your password has been reset', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('reset_password.html') 