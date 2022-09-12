from flask import Flask, jsonify, request, redirect, url_for, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.inspection import inspect
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email

app = Flask(__name__)
app.config.from_object("project.config.Config")
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Serializer(object):
    def serialize(self):
        return {c: getattr(self, c) for c in inspect(self).attrs.keys()}

    @staticmethod
    def serialize_list(lst):
        return [m.serialize() for m in lst]


class User(db.Model, Serializer, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    surname = db.Column(db.String(128), nullable=True)
    pre_name = db.Column(db.String(128), nullable=True)
    birthday = db.Column(db.String(128), nullable=True)
    address = db.Column(db.String(128), nullable=True)
    comments = db.Column(db.String(128), nullable=True)
    hobby = db.Column(db.String(128), nullable=True)
    email = db.Column(db.String(128), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def serialize(self):
        d = Serializer.serialize(self)
        del d['password']
        return d


#

class LoginForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired(), Email()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label='LOG ME IN!')


class UserForm(FlaskForm):
    surname = StringField(label='Surname', validators=[DataRequired()])
    pre_name = StringField(label='Pre Name', validators=[DataRequired()])
    birthday = StringField(label='Birthday', validators=[DataRequired()])
    address = StringField(label='Address', validators=[DataRequired()])
    comments = StringField(label='Comments', validators=[DataRequired()])
    hobby = StringField(label='Hobby', validators=[DataRequired()])
    email = StringField(label='Email', validators=[DataRequired()])
    password = StringField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label='Update')


@app.route("/api/login", methods=['POST'])
def api_login():
    email = request.json.get('email', '')
    password = request.json.get('password', '')
    user = User.query.filter_by(email=email, password=password).first()
    if user:
        return jsonify(success=f"{email} You are currently logged in"), 200
    else:
        return jsonify(error="Unauthorized"), 401


@app.get('/api/users')
def results():
    users = User.query.all()
    return jsonify(User.serialize_list(users))


@app.route('/api/create', methods=['POST'])
def create_address_book():
    surname = request.json.get('surname', '')
    pre_name = request.json.get('pre_name', '')
    birthday = request.json.get('birthday', '')
    address = request.json.get('address', '')
    comments = request.json.get('comments', '')
    hobby = request.json.get('hobby', '')
    email = request.json.get('email', '')
    password = request.json.get('password', '')
    is_admin = request.json.get('is_admin', '')
    if is_admin:
        new_user = User(surname=surname, pre_name=pre_name,
                        birthday=birthday, address=address,
                        comments=comments, hobby=hobby,
                        email=email, password=password, is_admin=True)
    else:
        new_user = User(surname=surname, pre_name=pre_name,
                        birthday=birthday, address=address,
                        comments=comments, hobby=hobby,
                        email=email, password=password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'success': 'User created'}), 200


@app.route('/api/update/<int:user_id>', methods=['PUT'])
def update_address_book(user_id):
    surname = request.json.get('surname', '')
    pre_name = request.json.get('pre_name', '')
    birthday = request.json.get('birthday', '')
    address = request.json.get('address', '')
    comments = request.json.get('comments', '')
    hobby = request.json.get('hobby', '')
    email = request.json.get('email', '')
    user = User.query.get(user_id)
    if user:
        if surname:
            user.surname = surname
        if pre_name:
            user.pre_name = pre_name
        if birthday:
            user.birthday = birthday
        if address:
            user.address = address
        if comments:
            user.comments = comments
        if hobby:
            user.hobby = hobby
        if email:
            user.email = email
        db.session.commit()
        return jsonify({'success': f'User updated with id {user_id}'})
    else:
        return jsonify(error="Bad request"), 400


@app.route('/api/update/<int:admin_id>/<int:user_id>', methods=['PUT'])
def admin_update_address_book(admin_id, user_id):
    admin_user = User.query.filter_by(id=admin_id, is_admin=True).first()
    if admin_user:
        surname = request.json.get('surname', '')
        pre_name = request.json.get('pre_name', '')
        birthday = request.json.get('birthday', '')
        address = request.json.get('address', '')
        comments = request.json.get('comments', '')
        hobby = request.json.get('hobby', '')
        email = request.json.get('email', '')
        user = User.query.get(user_id)
        if user:
            if surname:
                user.surname = surname
            if pre_name:
                user.pre_name = pre_name
            if birthday:
                user.birthday = birthday
            if address:
                user.address = address
            if comments:
                user.comments = comments
            if hobby:
                user.hobby = hobby
            if email:
                user.email = email
            db.session.commit()
            return jsonify({'success': f'User updated with id {user_id}'})
        else:
            return jsonify(error="This user doesn't exist"), 400
    else:
        return jsonify(error='Unauthorized'), 401


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = User.query.filter_by(email=login_form.email.data).first()
        if user is not None:
            if user.password == login_form.password.data:
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Password incorrect,try again.', category='danger')
        else:
            flash('That email does not exist,please try again.', category='danger')
    return render_template("login.html", form=login_form)


@app.route('/', methods=['GET', 'POST'])
@login_required
def dashboard():
    user = current_user
    if user.is_admin:
        users = User.query.all()
        return render_template("admin-dashboard.html", users=users)
    else:
        return render_template("dashboard.html", user=user)


@app.route('/user-edit/<user_id>', methods=['GET', 'POST'])
@login_required
def user_edit(user_id):
    user = User.query.get(user_id)
    edit_form = UserForm(
        surname=user.surname,
        pre_name=user.pre_name,
        birthday=user.birthday,
        address=user.address,
        comments=user.comments,
        hobby=user.hobby,
        email=user.email,
        password=user.password
    )
    if edit_form.validate_on_submit():
        user.surname = edit_form.surname.data
        user.pre_name = edit_form.pre_name.data
        user.birthday = edit_form.birthday.data
        user.address = edit_form.address.data
        user.comments = edit_form.comments.data
        user.hobby = edit_form.hobby.data
        user.email = edit_form.email.data
        user.password = edit_form.password.data
        db.session.commit()
        return redirect(url_for("dashboard"))
    return render_template("user-form.html", form=edit_form, user=user)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
