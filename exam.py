from flask import Flask, jsonify, request
import psycopg2  # pip install psycopg2
from flask_bcrypt import Bcrypt  # pip install flask-bcrypt
import jwt  # pip install pyjwt
import datetime

app = Flask(__name__)

# Database connection configuration
DB_HOST = 'localhost'
DB_NAME = 'postgres'
DB_USER = 'postgres'
DB_PASSWORD = '1616'

# Your secret key to sign JWT tokens
SECRET_KEY = "this is a secret key this is a secret keyyyy!!!!"


# Function to get a database connection
def get_db_connection():
    connection = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    return connection





# Create the 'questions' table if it doesn't exist
def create_questions_table_if_not_exists():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS questions (
            question_id SERIAL PRIMARY KEY,
            question TEXT NOT NULL,
            subject TEXT NOT NULL,
            correct_answer TEXT NOT NULL
        );
    """)
    connection.commit()
    cursor.close()
    connection.close()
    


# Create the 'users' table if it doesn't exist
def create_users_table_if_not_exists():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
           
        );
    """)
    connection.commit()
    cursor.close()
    connection.close()


# Create the 'users' table if it doesn't exist
def create_answer_table_if_not_exists():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
      CREATE TABLE IF NOT EXISTS user_answers (
    user_answer_id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    question_id TEXT NOT NULL,
    Submitted_answer TEXT NOT NULL
  
);

    """)
    connection.commit()
    cursor.close()
    connection.close()
create_questions_table_if_not_exists()
create_answer_table_if_not_exists()
create_users_table_if_not_exists()


bcrypt = Bcrypt()


def encode_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')


def check_password(hashed_password, password):
    return bcrypt.check_password_hash(hashed_password, password)


def decode_token(jwt_token):
    try:
        decoded_token_payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=["HS256"])
        return decoded_token_payload
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired!"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token!"}), 401

#user sign-up api
@app.route('/sign-up', methods=['POST'])
def register_user():
    username = request.json['username']
    password = request.json['password']
    hashed_password = encode_password(password)
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
            INSERT INTO users (username, password) VALUES (%s, %s);
        """, (username, hashed_password))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message": "User registered successfully."}), 201

#user login api
@app.route('/login', methods=['POST'])
def login_user():
    username = request.json['username']
    password = request.json['password']
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM users WHERE username = %s;", (username,))
    user = cursor.fetchone()

    if user is None:
        return jsonify({"message": "Invalid username or password."}), 401
    stored_hashed_password = user[2]
    
    if not check_password(stored_hashed_password, password):
        return jsonify({"message": "Invalid username or password."}), 401
    payload = {
        'username': username,
        'user_id': user[0],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  
    }
  
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    cursor.close()
    connection.close()
    return jsonify({
        "message": "Login successful.",
        "token": token
    }), 200


@app.route('/create_questions', methods=['POST'])
def create_task():
    subject = request.json['subject']
    question = request.json['question']
    correct_answer = request.json['correct_answer']
    

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
                   INSERT INTO questions (subject, question,correct_answer) VALUES (%s, %s,%s);
                   """, (subject, question,correct_answer))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message": "Task created successfully"}), 201


#user can get the questions
@app.route('/get-questions', methods=['GET'])
def get_questions():
    subject = request.args.get('subject') 
    jwt_token = request.headers.get('Authorization')  
    decoded_token_payload = decode_token(jwt_token)  
    user_id = decoded_token_payload['user_id']  
    


    if decoded_token_payload is None:
    
        return jsonify({"error": "Invalid or expired token"}), 401
    else:
     connection = get_db_connection()
     cursor = connection.cursor()
     query = "SELECT * FROM questions WHERE subject = %s"
     cursor.execute(query, (subject,))
     questions = cursor.fetchall()

    cursor.close()
    connection.close()

    if questions:
     result = [
        { "question_id": question[0],"question": question[1], "subject": question[2]}
        for question in questions
    ]
     return jsonify(result), 200
 
    else:
      return jsonify({"message": "no question found or check the subject"}), 404



#user can submit the answer
@app.route('/submit-answer', methods=['POST'])
def submit_answer():
    jwt_token = request.headers.get('Authorization')
    
    decoded_token_payload = decode_token(jwt_token)
    user_id=decoded_token_payload['user_id']  
    
    question_id = request.json['question_id']
    submitted_answer = request.json['submitted_answer']


    if decoded_token_payload is None:
    
        return jsonify({"error": "Invalid or expired token"}), 401
    else:


     connection = get_db_connection()
     cursor = connection.cursor()
     cursor.execute("""
        INSERT INTO user_answers (user_id,question_id,submitted_answer)
        VALUES (%s, %s,%s);
    """, (user_id,question_id,submitted_answer))

    connection.commit()
    cursor.close()
    connection.close()

    return jsonify({"message": "Answer submitted successfully"}), 201


@app.route('/get-results', methods=['GET'])
def get_results():
    jwt_token = request.headers.get('Authorization')
    decoded_token_payload = decode_token(jwt_token)

    if decoded_token_payload is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    user_id = decoded_token_payload['user_id']

    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT question_id, submitted_answer FROM user_answers WHERE user_id = %s;", 
                   (str(user_id),))
    user_answers = cursor.fetchall()
    score_count = 0
    total_questions = len(user_answers)

    for question_id, submitted_answer in user_answers:
        cursor.execute("SELECT correct_answer FROM questions WHERE question_id = %s;", (question_id,))
        correct_answer = cursor.fetchone()

        if correct_answer and submitted_answer.lower() == correct_answer[0].lower():
            score_count += 1

    cursor.close()
    connection.close()

    return jsonify({
        "total_questions": total_questions,
        "score": score_count, 
    }), 200
    
if __name__ == '__main__':
    app.run(debug=True)
