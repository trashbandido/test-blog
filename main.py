import smtplib
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
import os
from smtplib import SMTP

# Import your forms from the forms.py
from forms import CreatePostForm, RegistrationForm, LoginForm, CommentForm

SENDER = os.environ.get("EMAIL")
SENDER_PASSWORD = os.environ.get("EMAIL_PASSWORD")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)
gravatar = Gravatar(
    app=app,
    size=100,
)

login_manager = LoginManager(app=app)

@login_manager.user_loader
def load_user(user_id):
    user = db.session.execute(db.select(User).where(User.id == user_id)).scalar()
    if user is not None:
        return user
    return None



# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy()
db.init_app(app)


def admin_only(function):
    @wraps(wrapped=function)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(code=403)
        else:
            return function(*args, **kwargs)
    return wrapper


# CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(256), unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    blog_posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="blog_posts")
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="blog_post")



class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    blog_post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    blog_post = relationship("BlogPost", back_populates="comments")




with app.app_context():
    db.create_all()


@app.route('/register', methods=["GET", "POST"])
def register():
    r_form = RegistrationForm()
    if r_form.validate_on_submit():
        if db.session.execute(db.select(User).where(User.email == r_form.email.data)).scalar():
            flash(message="This user already exists. Login instead.", category="Error")
            return redirect(url_for("login"))
        else:
            new_user = User(name=r_form.name.data,
                            email=r_form.email.data,
                            password=generate_password_hash(password=r_form.password.data, method="pbkdf2:sha256", salt_length=10)
                            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=r_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    l_form = LoginForm()
    if l_form.validate_on_submit():
        queried_user = db.session.execute(db.select(User).where(User.email == l_form.email.data)).scalar()
        if queried_user and check_password_hash(pwhash=queried_user.password, password=l_form.password.data):
            login_user(queried_user)
            return redirect(url_for("get_all_posts"))
        else:
            flash(message="Incorrect credentials. Please try again.", category="Error")
            redirect(url_for("login"))
    return render_template("login.html", form=l_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    requested_comments = requested_post.comments
    c_form = CommentForm()
    if c_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash(message="You need to login to comment.")
            return redirect(url_for("login"))
        else:
            new_comment = Comment(
                text=c_form.comment_body.data,
                comment_author=current_user,
                blog_post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
    return render_template("post.html", post=requested_post, form=c_form, comments=requested_comments)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        body = f"Name: {request.form['name']}\n" \
               f"Email: {request.form['email']}\n" \
               f"Phone: {request.form['phone']}\n" \
               f"Message: {request.form['message']}"

        with SMTP(host="smtp.gmail.com") as connection:
            connection.starttls()
            connection.login(user=SENDER, password=SENDER_PASSWORD)
            connection.sendmail(
                from_addr=SENDER,
                to_addrs=SENDER,
                msg=f"Subject: Blog Contact \n\n{body}"
            )
        return redirect(url_for("contact"))
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=False, port=8080)

