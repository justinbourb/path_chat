from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, \
    TextAreaField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, \
    Length
from flask_babel import _, lazy_gettext as _l
from app.models import User
from flask_login import current_user


class LoginForm(FlaskForm):
    email = StringField(_l('E-mail'), validators=[DataRequired()])
    password = PasswordField(_l('Password'), validators=[DataRequired()])
    remember_me = BooleanField(_l('Remember Me'))
    submit = SubmitField(_l('Sign In'))


class RegistrationForm(FlaskForm):
    first_name = StringField(_l('First Name'), validators=[DataRequired()])
    last_name = StringField(_l('Last Name'), validators=[DataRequired()])
    email = StringField(_l('Email'), validators=[DataRequired(), Email()])
    password = PasswordField(_l('Password'), validators=[DataRequired()])
    password2 = PasswordField(
        _l('Repeat Password'), validators=[DataRequired(),
                                           EqualTo('password')])
    address_1 = StringField(_l('Address 1'), validators=[DataRequired()])
    address_2 = StringField(_l('Address 2'), validators=[DataRequired()])
    city = StringField(_l('City'), validators=[DataRequired()])
    state = StringField(_l('State'), validators=[DataRequired()])
    zipcode = StringField(_l('Zipcode'), validators=[DataRequired()])
    telephone = StringField(_l('Telephone'), validators=[DataRequired()])
    submit = SubmitField(_l('Submit'))

    ''' not in use
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError(_('Please use a different username.'))
    '''

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError(_('Please use a different email address.'))


class ResetPasswordRequestForm(FlaskForm):
    email = StringField(_l('Email'), validators=[DataRequired(), Email()])
    submit = SubmitField(_l('Request Password Reset'))


class ResetPasswordForm(FlaskForm):
    password = PasswordField(_l('Password'), validators=[DataRequired()])
    password2 = PasswordField(
        _l('Repeat Password'), validators=[DataRequired(),
                                           EqualTo('password')])
    submit = SubmitField(_l('Request Password Reset'))

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField(_l('Current Password'), validators=[DataRequired()])
    new_password = PasswordField(_l('New Password'), validators=[DataRequired()])
    new_password2 = PasswordField(
        _l('Repeat New Password'), validators=[DataRequired(),
                                           EqualTo('new_password')])
    submit = SubmitField(_l('Change Password'))

    def validate_current_password(self, current_password):
        if not current_user.check_password(current_password.data):
            raise ValidationError(_('Invalid current password, please try again.'))


class EditProfileForm(FlaskForm):
    first_name = StringField(_l('First Name'), validators=[DataRequired()])
    last_name = StringField(_l('Last Name'), validators=[DataRequired()])
    email = StringField(_l('Email'), validators=[DataRequired(), Email()])
    address_1 = StringField(_l('Address 1'), validators=[DataRequired()])
    address_2 = StringField(_l('Address 2'), validators=[DataRequired()])
    city = StringField(_l('City'), validators=[DataRequired()])
    state = StringField(_l('State'), validators=[DataRequired()])
    zipcode = StringField(_l('Zipcode'), validators=[DataRequired()])
    telephone = StringField(_l('Telephone'), validators=[DataRequired()])
    submit = SubmitField(_l('Submit'))

class PostForm(FlaskForm):
    post = TextAreaField(_l('Say something'), validators=[DataRequired()])
    submit = SubmitField(_l('Submit'))
