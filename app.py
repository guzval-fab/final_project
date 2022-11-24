from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy import Column, Integer, String, create_engine, Boolean, ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
from jwt import encode, decode
import datetime
from functools import wraps
from logger import logger

app = Flask(__name__)

app.config['SECRET_KEY']='Th1s1ss3cr3t'
app.config['SQLALCHEMY_DATABASE_URI']='postgresql://postgres:password@localhost/movies'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
Base = declarative_base()
engine = create_engine('postgresql://postgres:password@localhost/movies')
db = SQLAlchemy(app)

class Users(Base, db.Model):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    public_id = Column(String)
    name = Column(String(50),nullable=False)
    last_name = Column(String(50),nullable=False)
    phone_number = Column(Integer,nullable=False)
    email = Column(String(70), unique=True,nullable=False)
    password = Column(String(250),nullable=False)
    admin = Column(Boolean)

class Movies(Base, db.Model):
   __tablename__ = 'movies'
   id = Column(Integer, primary_key=True)
   title= Column(String(150),nullable=False)
   poster_url= Column(String(150),nullable=False)
   rate = Column(String(150),nullable=False)
   schedules = relationship("Showtimes", backref="shows")

class Showtimes(Base,db.Model):
   __tablename__ = 'showtimes'
   id = Column(Integer, primary_key=True)
   movie_id= Column(Integer,ForeignKey("movies.id"))
   show = Column(String(150))

class Tickets(Base,db.Model):
   __tablename__ = 'tickets'
   id = Column(Integer, primary_key=True)
   show_id = Column(Integer,ForeignKey("showtimes.id"))
   movie_id= Column(Integer,ForeignKey("movies.id"))
   seat = Column(String)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):

      if 'tokens' in request.headers:
         token = request.headers['tokens']

      if not token:
         return jsonify({'message': 'a valid token is missing'}), 400

      try:
           data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
         
      except:
         return jsonify({'message': 'token is invalid'}), 400

      return f( *args, **kwargs)
   return decorator

@app.route('/register', methods=['POST'])
def signup_user():  
 data = request.get_json()  

 hashed_password = generate_password_hash(data['password'], method='sha256')
 
 new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], last_name=data['last_name'], email=data['email'],password=hashed_password, admin=False, phone_number=data['phone_number']) 
 db.session.add(new_user)  
 db.session.commit()    

 return jsonify({'message': 'registered successfully'})

@app.route('/login', methods=['POST'])  
def login_user(): 
 
  auth = request.authorization   

  if not auth or not auth.username or not auth.password:  
     return jsonify({'Unable to login': 'email or password missing!!'}), 400    

  with engine.connect() as con:
    user = con.execute(f"select * from users where email = '{auth.username}'").one()
       
  if check_password_hash(user[6], auth.password):  
     token = jwt.encode({'public_id': user[1], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])  
     return jsonify({'token' : token}) 

  return jsonify({'Unable to login': 'Either email or password incorrect'}), 400

@app.route('/index', methods=['GET'])
def get_all_movies():  
   #with engine.connect() as con:
    #movie = con.execute(f"select * from movies")
   movies = Movies.query.all()
   showtimes = Showtimes.query.all()
   result_shows = []   

   for showss in showtimes:   
       user_data = {   
      'id' : showss.id, 
      'id_movie' : showss.movie_id, 
      'show': showss.show,
       }
       result_shows.append(user_data)

   result = []   

   for movie in movies:   
       user_data = {   
      'id' : movie.id, 
      'title' : movie.title, 
      'poster_url': movie.poster_url,
      'rate' : movie.rate,
      'shows' : {
		      "show":result_shows[1], 
	         },
       }
       result.append(user_data)   

   return jsonify({'movies': result})

@app.route('/purchase', methods=['post'])
@token_required
def purchase_tickets():
   data = request.get_json()
   new_ticket = Tickets(show_id=data['show_id'],movie_id=data['movie_id'],seat=data['seat'])
   db.session.add(new_ticket)
   db.session.commit()
   return jsonify({'message': 'Your ticket was purchased'})

@app.route('/check', methods=['delete'])
@token_required
def check_tickets():
   return jsonify({'message': 'You currently have tickets: '})

@app.route('/cancel', methods=['delete'])
@token_required
def cancel_tickets():
   return jsonify({'message': 'You\'ve successfully cancelled your ticket: '})


if __name__ == "__main__":
    app.run(debug=True)



