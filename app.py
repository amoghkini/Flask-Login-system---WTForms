from flask import Flask, render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed,FileField
from flask_migrate import Migrate
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, FloatField, DateField, TimeField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo,ValidationError, Optional
from flask_login import LoginManager,UserMixin, login_user, current_user, logout_user,login_required
import secrets
import os
from PIL import Image
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import smtplib
from email.message import EmailMessage

app = Flask(__name__)
app.config['SECRET_KEY'] = 'AMOGH kini'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)
migrate = Migrate(app,db)
bcrypt = Bcrypt(app) 
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

email = EmailMessage()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class CommaFloatField(FloatField):
    """
    Subclass that handles floats of this format 1.2 or 1,2.        
    """
    def process_formdata(self, valuelist):
        if valuelist:
            try:
                self.data = float(valuelist[0].replace(",", ""))
            except ValueError:
                self.data = None
                raise ValueError(self.gettext('Not a valid float value'))
            
class User(db.Model,UserMixin):
    id                  = db.Column(db.Integer, primary_key=True)
    username            = db.Column(db.String(20), unique=True, nullable=False)
    firstName           = db.Column(db.String(120), unique=False, nullable=False)
    lastName            = db.Column(db.String(120), unique=False, nullable=False)
    email               = db.Column(db.String(120), unique=True, nullable=False)
    image_file          = db.Column(db.String(20), nullable=False,default='default.jpg')
    password            = db.Column(db.String(60), nullable=False)
    accountCreationDate = db.Column(db.DateTime, nullable=False,default=datetime.utcnow)
    noOfActiveCards     = db.Column(db.Integer, nullable=True)
    noOfDisabledCardds  = db.Column(db.Integer, nullable=True)

    
    def get_reset_token(self,epires_sec = 1800):
        s = Serializer(app.config["SECRET_KEY"], epires_sec)
        return s.dumps({'user_id':self.id}).decode('utf-8')

       
    @staticmethod
    def verify_reset_token(token):
        print("token",token)
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)
    
    def __rep__(self):
        return f"User('{self.username}','{self.email}','{self.image_file}')"


class RegistrationForm(FlaskForm):
    firstName = StringField('First Name', validators=[DataRequired(), Length(min=2, max=20)], render_kw={"placeholder": "First name"})
    lastName = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Last name"})
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Username"})
    email   = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign up')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('This username is already taken. Please choose a different one')
 
    def validate_email(self, email):
        user = User.query.filter_by(username=email.data).first()
        if user:
            raise ValidationError('This email is already taken. Please choose a different one')
                        
class UpdateAccountForm(FlaskForm):
    firstName = StringField('First name', validators=[DataRequired(), Length(min=2, max=20)])
    lastName = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Last name"})
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Username"})
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={'readonly': True})
    picture = FileField('Update Profile picture',validators=[FileAllowed(['jpg','jpeg','png'])])
    submit = SubmitField('Update Details')
    
    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError(
                    'This username is already taken. Please choose a different one')
        
                
    def validate_email(self, email):
        if email.data != current_user.email:    
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError(
                    'This email is already taken. Please choose a different one')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Log in')

                 
class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with this email. You must register first')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

@app.route("/")
def home():
    print(" home page")
    return render_template('home.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/register', methods=['POST', 'GET'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        print("Inside submit")
        hash_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hash_password,firstName = form.firstName.data,lastName = form.lastName.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to login', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user and bcrypt.check_password_hash(user.password,form.password.data):
            login_user(user,remember=form.remember.data)
            next_page = request.args.get('next')
            if next_page:
                next_page.replace('/', '')
            print('next page',next_page)
            flash("Login successful!!! Please check email and password", 'succcess')
            return redirect(url_for(next_page)) if next_page else redirect(url_for('home'))
        else:
            flash("Login Unsuccessful!!! Please check email and password", 'danger')
        return redirect(url_for('login'))

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _,f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path,'static/profile_pic',picture_fn)
    output_size = (125,125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn

@app.route('/account', methods=['POST', 'GET'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.firstName = form.firstName.data
        current_user.lastName = form.lastName.data
        db.session.commit()
        flash("Your account has been updated","success")
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.firstName.data = current_user.firstName 
        form.lastName.data = current_user.lastName 
        
    image_file = url_for('static',filename='profile_pic/' + current_user.image_file)
    return render_template('account.html',image_file=image_file,form=form)



def form_mail(user):
    email['from'] = os.environ.get('EMAIL_USER')
    email['to'] = user.email
    email['subject'] = 'Password Reset Request'
    
    
def send_reset_email(user):
    token = user.get_reset_token()
    form_mail(user)
    message  = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    
    #email.set_content(message)
    #smtp = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    #smtp.login('yourusername', 'password')
    #smtp.send_message(email)
    #smtp.close()
    print("Mail sent")
    print(message)
    
    
    

    
@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', form=form)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
    

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500
    
if __name__ == "__main__":
    app.run(debug=True,port=5003)
