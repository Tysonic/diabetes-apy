from flask import Flask, request, flash
from flask_cors import CORS
import pandas as pd
import pickle
from flask import Blueprint
from flask_login import logout_user, login_required, login_user, current_user, UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
CORS(app)
login_manager = LoginManager()
login_manager.init_app(app)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SECRET_KEY"] = "fljsfjaiofuifvioadfhuefslscdufhcvjkduaweuo"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "DiabetesSystem")
db = SQLAlchemy(app)
Migrate(app, db)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user):
    return User.query.get(user)

@app.route("/")
def index():
    return "<h>this is a backend api for predicting diabetes</h1>"


@app.route('/predictions', methods=["POST", 'GET'])
def predictions():
    col=['pregnancies', 'glucose', 'diastolic', 'triceps', 'insulin', 'bmi', 'dpf', 'age']
    columns = ["Pregnancies","Glucose","BloodPressure","SkinThickness","Insulin","BMI","DiabetesPedigreeFunction","Age"]


    with open('Notebook/pickle_model.pkl', 'rb') as file:
        model = pickle.load(file)

    data = request.json
    if data is None:
        return {"result": "bad request"}
    else:

        df = pd.DataFrame(data,index=[0])
        df[df.columns]=df[df.columns].astype(float)
        if "weight" not in df.columns:
            if 'height' in df.columns:
                df = df.drop('height', axis=1)
        else:
            df['BMI'] = df['weight'] / df['height']
            df = df.drop(['weight', 'height'], axis=1)
        df = df.reindex(columns, axis=1)
        pred = model.predict(df)
        return {'result': int(pred)}
account_blueprint = Blueprint('users', __name__, template_folder="templates")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = request.json

    if User.query.filter_by(email=form["email"]).first():
        return {'result' : "your email has already been registered"}
    if User.query.filter_by(username=form["username"]).first():
        return {'result':"The User Name has already been taken Please Choose another name"}
    new_user = User(username=form['username'].lower(), email=form['email'].lower(), password=form['password'])
    db.session.add(new_user)
    new_client = Records(username = form['username'])
    db.session.add(new_client)
    db.session.commit()
    return {'result':'success'}



@app.route("/login", methods=['POST', 'GET'])
def login():
    form = request.json

    user = User.query.filter_by(email=form['email'].lower()).first()
    if user is not None and check_password_hash(user.password_hash, form['password']):
        login_user(user)
        return {'result':"success", 'user':current_user.username}
    return {"result":"failed"}

@login_required
@app.route("/status", methods=["POST", 'GET'])
def status():
    if current_user.is_authenticated:
        return "User is authenticated"
    return "user must authenticate"

@login_required
@app.route("/logout", methods=['GETT','POST'])
def logout():
    logout_user()
    return {"result":"Logged out successfully"}


class User(db.Model, UserMixin):
    __tablename__ = "User"
    id = db.Column(db.Integer, primary_key=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))

    def __init__(self, email, password, username):
        self.email = email
        self.password_hash = generate_password_hash(password)
        self.username = username

    def __repr__(self):
        return f"{self.email, self.password_hash, self.username}"



class Records(db.Model):
    __tablename__ = "Records"
    id = db.Column(db.Integer, primary_key=True, index=True)
    username = db.Column(db.String)
    glucose = db.Column(db.String)
    age = db.Column(db.String)
    height = db.Column(db.String)
    weight = db.Column(db.String)
    insulin = db.Column(db.String)
    diastolic = db.Column(db.String)
    triceps = db.Column(db.String)
    pregnancies = db.Column(db.String)

    def __init__(self, username,age="", height="",weight="", insulin="",diastolic="",triceps="",pregnancies=""):
        self.username=username
        self.age=age
        self.height=height
        self.weight=weight
        self.insulin = insulin
        self.diastolic=diastolic
        self.triceps=triceps
        self.pregnancies=pregnancies

    def __repr__(self):
        return f"{self.id, self.height, self.weight, self.insulin, self.diastolic, self.triceps, self.pregnancies}"


if __name__ == "__main__":
    app.run()

# ssl_context='adhoc'/// for https of local server
