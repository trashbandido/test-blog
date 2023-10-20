from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField, PasswordField
from wtforms.validators import DataRequired, URL, Length, Email
from flask_ckeditor import CKEditorField

# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# TODO: Create a RegisterForm to register new users
class RegistrationForm(FlaskForm):
    name = StringField(name="name", label="Name", validators=[DataRequired(), Length(max=256)])
    email = EmailField(name="email", label="Email", validators=[DataRequired(), Email(), Length(max=256)])
    password = PasswordField(name="password", label="Password", validators=[DataRequired()])
    submit = SubmitField(name="submit", label="Submit")


# TODO: Create a LoginForm to login existing users
class LoginForm(FlaskForm):
    email = EmailField(name="email", label="Email", validators=[DataRequired()])
    password = PasswordField(name="password", label="Password", validators=[DataRequired()])
    login = SubmitField(name="login", label="Log in")

# TODO: Create a CommentForm so users can leave comments below posts

class CommentForm(FlaskForm):
    comment_body = CKEditorField(name="comment", label="Comment", validators=[DataRequired()])
    submit = SubmitField(name="submit", label="Submit Comment")