from flask import Flask, render_template, flash, redirect, url_for,session, request, logging
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)

# config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '12345'
app.config['MYSQL_DB'] = 'flaskblog'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# initialize MySQL
mysql = MySQL(app)

Articles = Articles()

# HOME
@app.route('/')
def index():
    return render_template('home.html')

# ABOUT
@app.route('/about')
def about():
    return render_template('about.html')

# ARTICLES
@app.route('/articles')
def articles():
    return render_template('articles.html', articles=Articles)

# SINGLE ARTICLE
@app.route('/article/<string:id>/')
def article(id):
    return render_template('article.html', id=id)

# REGISTER FORM CLASS
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

# USER REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # create cursor
        cur = mysql.connection.cursor()

        # execute query
        cur.execute("INSERT INTO users(name, email, username,password) VALUES(%s, %s, %s, %s)", (name, email, username, password))

        # commit to DB
        mysql.connection.commit()

        # close connection
        cur.close()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))

    return render_template('register.html', form=form)

# user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # get form fields
        username = request.form['username']
        password_candidate = request.form['password']

        # create database cursor
        cur = mysql.connection.cursor()

        # get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # get stored hash; fetchone retrieves first instance
            data = cur.fetchone()
            password = data['password']

            # compare passwords
            if sha256_crypt.verify(password_candidate, password):
                # app.logger.info('PASSWORD MATCH')

                # PASSED
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid login"
                return render_template('login.html', error=error)

            # close connection
            cur.close()
        else:
            error = "Username not found"
            return render_template('login.html', error=error)

    return render_template('login.html')

# CHECK IF USER IS LOGGED IN
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, please log in', 'danger')
            return redirect(url_for('login'))
    return wrap

# LOGOUT
@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# DASHBOARD
@app.route('/dashboard')
@is_logged_in
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.secret_key='secret12345'
    app.run(debug=True)