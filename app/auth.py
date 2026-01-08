from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from .models import User
from . import db

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and not user.active:
            flash('Usuário desativado. Contate o administrador.', 'danger')
            return redirect(url_for('auth.login'))

        if user and user.check_password(password):
            user.failed_login_attempts = 0 # Reset attempts on success
            db.session.commit()
            
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
        else:
            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.active = False
                    db.session.commit()
                    flash('Usuário desativado por excesso de tentativas falhas. Solicite recuperação ao administrador.', 'danger')
                    return redirect(url_for('auth.login'))
                db.session.commit()
                
            flash('Login inválido. Verifique usuário e senha.', 'danger')
            
    return render_template('login.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not current_user.check_password(current_password):
        flash('Senha atual incorreta.', 'danger')
        return redirect(request.referrer or url_for('main.dashboard'))

    if new_password != confirm_password:
        flash('A nova senha e a confirmação não coincidem.', 'danger')
        return redirect(request.referrer or url_for('main.dashboard'))

    current_user.set_password(new_password)
    db.session.commit()

    flash('Senha alterada com sucesso.', 'success')
    return redirect(url_for('main.dashboard'))

@auth.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        identifier = request.form.get('identifier')
        user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
        
        if user:
            user.password_reset_requested = True
            db.session.commit()
        
        flash('Sua solicitação foi enviada ao administrador. Por favor, aguarde o reset da sua senha.', 'info')
        return redirect(url_for('auth.login'))
        
    return render_template('forgot_password.html')
