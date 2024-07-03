from flask import Flask, jsonify, render_template, request, redirect, make_response, url_for
from flask_jwt_extended import JWTManager, create_access_token, jwt_required as jwt_required_extended, get_jwt_identity
from pymongo import MongoClient
from flask_bcrypt import Bcrypt, check_password_hash
from bson import ObjectId
from flask.json.provider import JSONProvider
from functools import wraps
from werkzeug.utils import secure_filename
import certifi
import json
import jwt
import time
import os
#from datetime import datetime, timedelta

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = 'static/uploads'

ca = certifi.where()

client = MongoClient(host='localhost', port=27017)
db = client.junglegram
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'junglegram_secret_key'

#####################################################################################
# 이 부분은 코드를 건드리지 말고 그냥 두세요. 코드를 이해하지 못해도 상관없는 부분입니다.
#
# ObjectId 타입으로 되어있는 _id 필드는 Flask 의 jsonify 호출시 문제가 된다.
# 이를 처리하기 위해서 기본 JsonEncoder 가 아닌 custom encoder 를 사용한다.
# Custom encoder 는 다른 부분은 모두 기본 encoder 에 동작을 위임하고 ObjectId 타입만 직접 처리한다.
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)

class CustomJSONProvider(JSONProvider):
    def dumps(self, obj, **kwargs):
        return json.dumps(obj, **kwargs, cls=CustomJSONEncoder)

    def loads(self, s, **kwargs):
        return json.loads(s, **kwargs)


# 위에 정의되 custom encoder 를 사용하게끔 설정한다.
app.json = CustomJSONProvider(app)

# 여기까지 이해 못해도 그냥 넘어갈 코드입니다.
# #####################################################################################


@app.route('/')
def login():
    return render_template('login.html')

@app.route('/main', methods=['POST'])
def main():
    access_token = request.form['access-token']
    _id = jwt.decode(access_token, app.config['SECRET_KEY'], algorithms=['HS256'])['_id']
    temp = list(db.users.find())
    users = []
    for i in range(len(temp)):
        if str(temp[i]['_id']) != _id:
            users.append(temp[i])

    return render_template('main.html', users=users)

@app.route('/user', methods=['POST'])
def user_page():
    id = request.form["id"]
    user = db.users.find_one({"_id":ObjectId(id)})
    return render_template('user_page.html', user=user)

@app.route('/mypage', methods=['POST'])
def my_page():
    access_token = request.form['access-token']
    id = jwt.decode(access_token, app.config['SECRET_KEY'], algorithms=['HS256'])['_id']
    print(id)
    user = db.users.find_one({"_id":ObjectId(id)})
    print(user)
    return render_template('my_page.html', user=user)

@app.route('/user/register', methods=['POST']) 
def register() : 
    id_receive = request.form['id_give']
    pw_receive = request.form['pw_give']
    pw_hash = bcrypt.generate_password_hash(pw_receive).decode('utf-8')
    if db.accounts.count_documents({'id': id_receive}) == 0:
        db.accounts.insert_one({'id': id_receive, 'password': pw_hash})
        _id = db.accounts.find_one({'id': id_receive})['_id']
        return jsonify({'result': 'success', 'message': 'register success', '_id': _id})
    else:
        return jsonify({'result': 'failure', 'message': 'id already exists'})

@app.route('/user/insert', methods=['POST'])
def insert():
    result = request.form
    print(result)
    _id = result['_id']
    name = result['name']
    age = result['age']
    mbti = result['mbti']
    hobby = result['hobby']
    rgb = result['rgb']
    content = result['content']
    pic = request.files['pic']

    filename = secure_filename(pic.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    pic.save(file_path)
    doc = {
        '_id': ObjectId(_id),
        'name': name,
        'age': age,
        'mbti': mbti,
        'hobby': hobby,
        'rgb': rgb,
        'content': content,
        'image_path': file_path
    }
    db.users.insert_one(doc)
    return jsonify({'result': 'success'})

@app.route('/user/edit', methods=['POST'])
def edit():
    result = request.form
    token = result['token']
    name = result['name']
    age = result['age']
    mbti = result['mbti']
    hobby = result['hobby']
    rgb = result['rgb']
    content = result['content']
    pic = request.files['pic']
    filename = secure_filename(pic.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    pic.save(file_path)
    _id = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])['_id']
    db.users.update_one({'_id': ObjectId(_id)},{'$set':{'name':name ,'age':age,'mbti':mbti,'hobby':hobby,'rgb':rgb ,'content':content, 'image_path': file_path}})

    return jsonify({'result': 'success'})

@app.route('/user/login', methods=['POST']) 
def user_login() : 
    id = request.form['id']
    pw = request.form['pw']
    account = db.accounts.find_one({'id': id})
    _id = account['_id']
    _id = str(_id)
    if account:
        if check_password_hash(account['password'], pw):
            payload = {
                '_id': _id,
                #'pw' : account['password'],
                #만료기한 24시간
                'exp': time.time() + 86400
            }
            token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        
            #token 변수명 변경: token > access-token
            return jsonify({'result': 'success', 'access-token': token})
        
        else:
            return jsonify({'result': 'failure', 'message': 'pw doesnt exists'})
    else :
        return jsonify({'result': 'failure', 'message': 'id doesnt exists'})



@app.route('/user/check_id', methods=['GET']) 
def check_id() : 
    id_receive = request.args.get('id_give')

    if db.accounts.count_documents({'id': id_receive}) == 0:
        return jsonify({'result': 'success', 'message': 'usable id'})
    else:
        return jsonify({'result': 'failure', 'message': 'id already exists'})

@app.route('/check_token', methods=['GET'])
def check_token():
    access_token = request.headers.get('Authorization')
    if not access_token:
        return redirect('/login')
    return jsonify({'result': 'success'}) 



if __name__ == '__main__':
   app.run('0.0.0.0',port=5000,debug=True)
