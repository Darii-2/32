from flask import Flask, render_template, redirect, url_for, request, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps

app = Flask(__name__)
app.secret_key = 'secret_key_for_session'

login_manager = LoginManager()
login_manager.init_app(app)

# Створимо фейкових користувачів для прикладу
class User(UserMixin):
    def __init__(self, id, username, password, roles):
        self.id = id
        self.username = username
        self.password = password
        self.roles = roles
    
    def has_role(self, role):
        return role in self.roles

# Приклад користувачів
users = {
    'user1': User(1, 'user1', 'password1', ['ROLE_USER']),
    'admin1': User(2, 'admin1', 'password2', ['ROLE_ADMIN', 'ROLE_USER']),
}

@login_manager.user_loader
def load_user(user_id):
    return next((user for user in users.values() if str(user.id) == user_id), None)

# Декоратор для перевірки ролі
def requires_roles(*roles):
    def wrapper(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not any(current_user.has_role(role) for role in roles):
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return wrapper

# Головна сторінка
@app.route('/')
def index():
    if current_user.is_authenticated:
        if 'ROLE_ADMIN' in current_user.roles:
            return redirect(url_for('admin_page'))
        elif 'ROLE_USER' in current_user.roles:
            return redirect(url_for('user_page'))
    return redirect(url_for('login'))

# Сторінка для користувачів
@app.route('/user')
@login_required
@requires_roles('ROLE_USER')
def user_page():
    return f'Hello {current_user.username}, you are a regular user.'

# Сторінка для адміністраторів
@app.route('/admin')
@login_required
@requires_roles('ROLE_ADMIN')
def admin_page():
    return f'Hello {current_user.username}, you are an admin.'

# Сторінка для логіну
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if 'ROLE_ADMIN' in current_user.roles:
            return redirect(url_for('admin_page'))
        elif 'ROLE_USER' in current_user.roles:
            return redirect(url_for('user_page'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = users.get(username)
        if user and user.password == password:
            login_user(user)
            return redirect(url_for('index'))
        return 'Invalid credentials'
    
    return render_template('login.html')

# Вихід
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
