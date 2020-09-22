import os
from flask import Flask,jsonify ,request
from flask_restful import Resource,Api
from pymongo import MongoClient
import bcrypt
import spacy


app = Flask(__name__)

api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.CompareDB
users = db["Users"]

class Registration(Resource):
    def post(self):

        postData = request.get_json()

        username = postData["username"]
        password = postData["password"]

        if userExist(username):

            retJson ={
                "status":301,
                "message":"User already exist"
            }
            return jsonify(retJson)

        hashed_pass = bcrypt.hashpw(password.encode('utf8'),bcrypt.gensalt())

        users.insert({
                "Username":username,
                "Password":hashed_pass,
                "Tokens":6
        })

        retJson = {
            "status":200,
            "message":"You have successfully signed up !!!"
        }

        return jsonify(retJson)

class Detect(Resource):
    def post(self):
        postData = request.get_json()

        username = postData["username"]
        password = postData["password"]
        text1    = postData["text1"]
        text2    = postData["text2"]


        if not userExist(username):
            retJson ={
                "status": 301,
                "message": "Invalid Username"
            }

            return jsonify(retJson)

        correctpass = verifyPass(username,password)

        if not correctpass:
            retJson = {
                    "status":302,
                    "message":"Invalid Password"
                }
            return jsonify(retJson)

        num_tokens = countToken(username)

        if num_tokens <=0 :
            retJson = {
                "status": 303,
                "message": "You are out of token. Please refill !!!"
            }
            return jsonify(retJson)


        # Compare text in Spacy
        nlp = spacy.load("en_core_web_sm")
        text1 = nlp(text1)
        text2 = nlp(text1)

        ratio = text1.Similarity(text2)
    

        #text1 = nlp(text1)
        #text2 = nlp(text2)
        # Ratio is a number b/w 0 to 1 the closer to 1 , the more similar text1 and text2.
        
        #text1.similarity(text2)

        retJson = {
            "status": 200,
            "similarity":ratio,
            "message":"Similarity score claculated sccessfully."
        }

        current_token = countToken(username)

        users.update({
            "Username":username},{
            '$set':{"Tokens":current_token-1
            }
        })

        return jsonify(retJson)

class Refill(Resource):
    def post(self):

        postData = request.get_json()

        username = postData["username"]
        password = postData["admin_pw"]
        refill_amount = postData["refill"]

        if not userExist(username):
            retJson ={
                "status": 301,
                "message": "Invalid Username"
            }

            return jsonify(retJson)

        #correctpass = verifyPass(username,password)
        correctpass="12345"

        if not password == correctpass:
            retJson = {
                    "status":304,
                    "message":"Invalid Admin Password"
                }
            return jsonify(retJson)

        current_tokens = countToken(username)
        total_token = current_tokens + refill_amount

        users.update({
            "Username":username
        },
            {
            '$set':{"Tokens":total_token
            }
        })

        retJson = {
            "Status":200,
            "Total Token": total_token,
            "message": "Refilled successfully"
        }

        return jsonify(retJson)







def countToken(username):
    tokencount = users.find({"Username":username})[0]["Tokens"]
    return tokencount



def verifyPass(username,password):
    if not userExist(username):
        return False

    hashed_pw = users.find({"Username":username})[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'),hashed_pw) == hashed_pw:
        return True
    else:
        return False


def userExist(username):
    if users.find({"Username":username}).count() == 0:
        return False
    else:
        return True


api.add_resource(Registration,'/registration')
api.add_resource(Detect,'/detect')
api.add_resource(Refill,'/refill')


if __name__=="__main__":
    app.run(host="0.0.0.0",debug=True)
