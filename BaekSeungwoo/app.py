from flask import Flask, jsonify, render_template, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from flask_bcrypt import Bcrypt, check_password_hash
from bson import ObjectId
from flask.json.provider import JSONProvider


app = Flask(__name__)
import certifi

import json
import sys


ca = certifi.where()


# client = MongoClient('mongodb://ben:kakao1369!@15.164.217.10/?authSource=admin', 27017)
client = MongoClient(host='localhost', port=27017)

db = client.junglegram
bcrypt = Bcrypt(app)
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

## HTML을 주는 부분
@app.route('/')
def home():
   return render_template('login.html/')

@app.route('/user', methods=['POST'])
def show_user():
    id = request.form['id']
    user = db.users.find_one({'_id': ObjectId(id)})
    return render_template('user_page.html/', user=user)
    

@app.route('/insert', methods=['POST'])
def insert():
    result = request.form
    name = result['name']
    age = result['age']
    mbti = result['mbti']
    hobby = result['hobby']
    rgb = result['rgb']
    content = result['content']
    doc = {
        'name': name,
        'age': age,
        'mbti': mbti,
        'hobby': hobby,
        'rgb': rgb,
        'content': content
    }
    db.users.insert_one(doc)
   
    return jsonify({'result': 'success'})

@app.route('/edit', methods=['POST'])
def edit():
    result = request.form
    id= result['id']
    name = result['name']
    age = result['age']
    mbti = result['mbti']
    hobby = result['hobby']
    rgb = result['rgb']
    content = result['content']
    
    db.users.update_one({'_id': ObjectId(id)}, {'$set': {'name': name, 'age': age, 'mbti': mbti, 'hobby': hobby, 'rgb': rgb, 'content': content}})
   
    return jsonify({'result': 'success'})

@app.route('/users/register', methods=['POST']) 
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
    

@app.route('/users/check_id', methods=['GET']) 
def check_id() : 
    id_receive = request.args.get('id_give')

    if db.accounts.count_documents({'id': id_receive}) == 0:
        return jsonify({'result': 'success', 'message': 'usable id'})
    else:
        return jsonify({'result': 'failure', 'message': 'id already exists'})

@app.route('/users/login', methods=['GET']) 
def login() : 
    id = request.args.get('id')
    pw = request.args.get('pw')
    account = db.accounts.find_one({'id': id})
    if account:
        if check_password_hash(account['password'], pw):
            return jsonify({'result': 'success', 'message': 'login success'})
        else:
            return jsonify({'result': 'failure', 'message': 'id or pw doesnt exists'})
    else :
        return jsonify({'result': 'failure', 'message': 'id or pw doesnt exists'})



if __name__ == '__main__':
   app.run('0.0.0.0',port=5000,debug=True)