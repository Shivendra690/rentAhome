from flask import Flask,render_template,url_for,flash,redirect,request,logging,session

from flask_mysqldb import MySQL
#from flask.ext.wtf import Form
#from wtforms.validators import InputRequired
from wtforms import Form,BooleanField,StringField,TextAreaField,PasswordField,validators
from passlib.hash import sha256_crypt
from functools import wraps
from MySQLdb import escape_string as thwart
import gc



##from flask_debug import Debug
##Debug(app)


app= Flask(__name__)


# mysql configuration
app.config['MYSQL_HOST']='localhost'
app.config['MYSQL_USER']='root'
app.config['MYSQL_PASSWORD']='root123'
app.config['MYSQL_DB']='project_app'
app.config['MYSQL_CURSORCLASS']='DictCursor'

#init mysql
mysql= MySQL(app)

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/')
def home():
    return render_template('home.html')

    
class registerForm(Form):
    name= StringField('Name',[validators.Length(min=2,max=50)])
    username=StringField('Username',[validators.Length(min=2,max=50)])
    email= StringField('email',[validators.Length(min=6,max=50)])
    password=PasswordField('Password',[validators.DataRequired(),validators.EqualTo('confirm',message='Password do not match')])
    confirm= PasswordField('Confirm Password')
        
            
            
    #confirm= PasswordField('Confirm Password')

 

@app.route('/register/',methods=['GET','POST'])
def register():
    form= registerForm()
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        
        
        #create cursor to execute commands
        cur = mysql.connection.cursor()

         #execute querry
        cur.execute("INSERT INTO analyser(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))

               #commit to database
        mysql.connection.commit()
        

        #close connction
        cur.close()
        gc.collect()
        flash('Successfully Registered','success')
        
        session['logged_in'] = True
        session['username'] = username

        return redirect(url_for('dashboard'))

         #return render_template('Register.html')
    return render_template('register.html', form=form)


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM analyser WHERE username = (%s)",[username])

        
        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')

                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')




# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


@app.route('/ContactUs')
@is_logged_in
def ContactUs():
    return render_template('ContactUs.html')


@app.route('/phagwara')
@is_logged_in
def phagwara():
    return render_template('phagwara.html')


@app.route('/lawgate')
@is_logged_in
def lawgate():
    return render_template('lawgate.html')


@app.route('/jalandhar')
@is_logged_in
def jalandhar():
    return render_template('jalandhar.html')        

@app.route('/aboutus')
@is_logged_in
def aboutus():
    return render_template('aboutus.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.secret_key='secret123'
    app.run(debug=True)
