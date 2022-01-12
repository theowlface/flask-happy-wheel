#import Time
from datetime import datetime
from os import name
from threading import current_thread
#flask stuff
from flask import Flask, render_template, flash, redirect, request, session, url_for
# from flask.helpers import url_for
#time
from flask_moment import Moment
#forms for String, Password, Email 
from flask_wtf import FlaskForm
from sqlalchemy.orm import backref
from wtforms import StringField, SubmitField, PasswordField, EmailField, BooleanField, ValidationError
from wtforms.validators import DataRequired, Email, EqualTo, Length
#import hash generator for password
from werkzeug.security import generate_password_hash, check_password_hash
#import sql alchemy DB
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, login_manager, login_user, LoginManager, login_required, logout_user, current_user
import os
#Creating flask APP
app = Flask(__name__)
#current time 
moment = Moment(app)
#secret key for securly singing the session cookie
app.config["SECRET_KEY"] = "secret keeey"
#connecting DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
#initialize DB
db = SQLAlchemy(app)
#migrate
migrate = Migrate(app, db)

#flask login stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#Creating a class for user table
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    hash_pw = db.Column(db.String(50))
    email = db.Column(db.String(50), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow())
    orders =  db.relationship('Order', backref='user', lazy = True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    #hashing password
    @property
    def password(self):
        raise AttributeError('password is not readable attribute')

    @password.setter
    def password(self,password):
        self.hash_pw = generate_password_hash(password)

    def verify_password(self,password):
        return check_password_hash(self.hash_pw, password)

#creating a String                                                               
    def __repr__(self):
        return '<Name %r>' % self.name

#Creating a class for user table
class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    order_name = db.Column(db.String(50))
    date_added = db.Column(db.DateTime, default=datetime.utcnow())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

#Creating a class for Role table
class Role(db.Model):
    __tablename__ = 'roles' 
    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50), unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow())
    users = db.relationship('User', backref='role', lazy = True)

#class for sing up  Form 
class Singup_from(FlaskForm):
    first_name = StringField("First Name", validators=[DataRequired()],render_kw={'autofocus': True,})
    last_name = StringField("Last Name", validators=[DataRequired()])
    email = EmailField('Email address', validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    password_2 = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password_2', message = None)])
    role = StringField("Role")
    signup_btn = SubmitField("Sign up")

#Creating login class Form 
class login_form(FlaskForm):
    email = EmailField('Email address', validators=[DataRequired(), Email()], render_kw={'autofocus':True})
    password = PasswordField("Password", validators=[DataRequired()])
    login_btn = SubmitField("Log in")
#class for update info Form 
class Update_form(FlaskForm):
    first_name = StringField("First Name", validators=[DataRequired()],render_kw={'autofocus': True})
    last_name = StringField("Last Name", validators=[DataRequired()])
    email = EmailField('Email address', validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    update_btn = SubmitField("Update")

#class for update info Form 
class Order_form(FlaskForm):
    email = EmailField('Email address', validators=[DataRequired(), Email()])
    order = StringField("What is you Order", validators=[DataRequired()], render_kw={'autofocus': True})
    buy_btn = SubmitField('Buy')


#route for  Home page
@app.route('/')
def index():
    #render the template, and the current time 
    return render_template('index.html',current_time=datetime.utcnow())

#route for Contact page
@app.route('/contact')
def contact():
    return render_template('contact.html')

#route to handle signu up Page
@app.route('/signup', methods=['GET','POST'])
def signup():
    #set up the form fields
    form = Singup_from()
    first_name = None
    last_name = None
    email = None
    password = None
    password_2= None
    role_id = 2
    #if the request is POST, Validate the Form 
    if request.method == "POST":
        #search the user by email
        user = User.query.filter_by(email = form.email.data).first()
        # if user is not exist, add it to DB
        if user is None:
            #hash the password
            hash_pw = generate_password_hash(form.password.data,"sha256")
            #add user details
            user = User(first_name = form.first_name.data, last_name = form.last_name.data, email = form.email.data, hash_pw= hash_pw, role_id=role_id)
            db.session.add(user)
            db.session.commit()
            #go to log in page
            flash('signed up successfully ')
            return redirect(url_for('login'))
        
        # empty the fields
        first_name = form.first_name.data
        form.first_name.data = ""
        form.last_name.data = ""
        form.email.data = ""
        form.password.data = ""
        form.password_2.data = ""
        #if user already exist,show message that user already exist and go to 
        if user :
            flash ('User Aleady Exist')
            return redirect(url_for('login'))

    #return Sign up Page if reqest is get, flash a message 
    flash("We will not share your email with anyone")
    return render_template('singup.html',
        email=email, first_name = first_name, last_name = last_name, form=form, password=password, password_2=password_2)

# Creating login Page
@app.route('/login', methods=['GET','POST'])
def login():
    #set form fieldss
    password = None
    form = login_form()
    if request.method == "POST":
        check_user = User.query.filter_by(email = form.email.data).first()
        password = form.password.data
        if check_user:
            if check_password_hash(check_user.hash_pw, password):
                login_user(check_user)
                flash('login successfully')
                name=current_user.first_name
                return redirect(url_for('user', name=name))
            else:
                flash('Password is not Correct')
        else:
            flash('user does not exist')
    return render_template('login.html',form=form)

#creat logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('you have been logged out')
    return redirect(url_for('login'))

#route for USER page
@app.route('/user/<name>')
@login_required
def user(name):
    name=current_user.first_name
    orders = Order.query.order_by(Order.date_added)
    #if there's user in session then go to user page
    return render_template('user.html', name=name,orders=orders)

#route for user to update personal infomation
@app.route('/user/update/<int:id>', methods=['GET','POST'])
@login_required
def update_current_user(id):
    #set update form
    form = Update_form()
    #get user id, and update user information to DB
    #get the information from users and update it in DB
    user_to_update = User.query.get_or_404(id)
    if request.method == "POST":
        user_to_update.first_name = request.form['first_name']
        user_to_update.last_name = request.form['last_name']
        user_to_update.email = request.form['email']
        user_to_update.password = request.form['password']
        try:
            db.session.commit()
            #flash message that updated successfully sta
            flash("user updated successflly")
            return render_template('user.html', form=form, user_to_update = user_to_update, id=id)
        except :
            flash("Error!! somethin went wronge")   
    return render_template('update_current_user.html', form = form, user_to_update = user_to_update, id=id )

#route for admin page
@app.route('/admin')
@login_required
def admin():
    # our_users = User.query.order_by(User.date_added)
    return render_template ('admin.html')

#route show user id DB
@app.route('/admin/show')
@login_required
def show_users():
    our_users = User.query.order_by(User.date_added)
    our_orders = Order.query.order_by(Order.date_added)
    our_roles = Role.query.order_by(Role.role_name)
    return render_template('show_users.html',our_users= our_users, our_orders=our_orders, our_roles=our_roles)


#route for admin to add user
@app.route('/admin/add-user',methods=['GET','POST'])
@login_required
def add_user():
        #set up the form fields
    form = Singup_from()
    first_name = None
    last_name = None
    email = None
    password = None
    password_2= None
    role_id = 2
    #if the request is POST, Validate the Form 
    if request.method == "POST":
        #search the user by email
        check_user = User.query.filter_by(email = form.email.data).first()
        # if user is not exist, add it to DB
        if check_user is None:
            #hash the password
            hash_pw = generate_password_hash(form.password.data,"sha256")
            #add user details
            user = User(first_name = form.first_name.data, last_name = form.last_name.data, email = form.email.data, hash_pw= hash_pw, role_id = role_id)
            db.session.add(user)
            db.session.commit()
            #go to log in page
            flash('User added successfully ')
            return redirect(url_for('add_user'))
        # empty the fields
        form.first_name.data = ""
        form.last_name.data = ""
        form.email.data = ""
        form.password.data = ""
        form.password_2.data = ""
        #if user already exist,show message that user already exist and go to 
        if check_user :
            flash ('User Aleady Exist')
            return redirect(url_for('add_user'))
    return render_template('add_user.html', form=form, email=email, first_name = first_name, last_name = last_name, password=password, password_2=password_2)

#roure for admin to update user details
@app.route('/admin/update-user/<int:id>', methods=['GET','POST'])
@login_required
def update(id):
    #set update form
    form = Update_form()
    #get user id, and update user information to DB
    #get the information from users and update it in DB
    user_to_update = User.query.get_or_404(id)
    if request.method == "POST":
            user_to_update.first_name = request.form['first_name']
            user_to_update.last_name = request.form['last_name']
            user_to_update.email = request.form['email']
            user_to_update.password = request.form['password']
            try:
                db.session.commit()
                #flash message that updated successfully sta
                flash("user updated successflly")
                return render_template('update_info.html',form=form, user_to_update = user_to_update)
            except :
                flash("Error!! somethin went wronge")
    return render_template('update_info.html', form = form, user_to_update = user_to_update )

# route for admin to delete user Delete User from DB
@app.route('/delete/<int:id>', methods=['GET','POST'])
@login_required
def delete_user(id):
        user_to_delete = User.query.get_or_404(id)
        if current_user.role_id == 1:
            try:
                db.session.delete(user_to_delete)
                db.session.commit()
                flash("User Deleted Successfully")
                our_users = User.query.order_by(User.date_added)
                return render_template('show_users.html',our_users=our_users,id = id)
            except :
                flash("Error!! somethin went wronge")
        else:
            flash("You don't have permission to this action")
            return redirect(url_for('index'))

#Custom Error pages
#Invalid URL
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
#Internal Server Error
@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


#Jason 
@app.route('/data')
def jaspn_data():
    return {'Time' : datetime.utcnow()}
    







#route for admin to add Order to users
@app.route('/admin/add-order/', methods=['GET','POST'])
@login_required
def add_order():
    form = Order_form()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email = form.email.data).first()
            order =Order(order_name=form.order.data, user_id=user.id)
            form.order.data = ""
            form.email.data = ""
            db.session.add(order)
            db.session.commit()
            flash('Order Added Succsessfully')
        except :
            flash('Something Went Wronge !!')

        
    return render_template('add_order.html',form=form)



#rurrent user delete Order
@app.route('/admin/delete-oreder/<int:id>', methods=['GET','POST'])
@login_required
def delete_order(id):
    order_to_delete = Order.query.get_or_404(id)
    if current_user.role_id == 1:
        try:
            db.session.delete(order_to_delete)
            db.session.commit()
            flash("User Deleted Successfully")
            return redirect(url_for('show_users', order_to_delete=order_to_delete, id = id))
        except :
            flash("Error!! somethin went wronge")
    else:
        flash("You don't have permission to this action")
        return redirect(url_for('index'))



# --------------------------
#route for Current user add order
@app.route('/user/add-order/<int:id>', methods=['GET','POST'])
@login_required
def current_user_add_order(id):
    form = Order_form()
    if request.method == 'POST':
        try:
            order =Order(order_name=form.order.data, user_id=current_user.id)
            form.order.data = ""
            db.session.add(order)
            db.session.commit()
            flash('Order Added Succsessfully')
        except:
            flash('Somthing went wronge')
        
    return render_template('add_order_current_user.html',form=form, id=id)

#route for user to delete order



'''
Migrate DB
flask db init
flask db migrate
'''
