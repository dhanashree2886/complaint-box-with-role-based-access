from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# MongoDB connection string
MONGO_URI = "mongodb+srv://dhanashree:2886dhanashree@database.6fbsadp.mongodb.net/"
client = MongoClient(MONGO_URI)
db = client['complaint_box_db']

users_col = db['users']
complaints_col = db['complaints']

@app.route('/')
def index():
    if 'user_id' in session:
        if session['role'] == 'student':
            return redirect(url_for('student_dashboard'))
        elif session['role'] == 'faculty':
            return redirect(url_for('faculty_dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        if role not in ('student', 'faculty'):
            flash('Invalid role selected')
            return redirect(url_for('register'))
        if users_col.find_one({'username': username}):
            flash('Username already exists')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        users_col.insert_one({
            'username': username,
            'password': hashed_password,
            'role': role
        })
        flash('Registered successfully! Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users_col.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            session['role'] = user['role']
            flash('Logged in successfully')
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out')
    return redirect(url_for('login'))

@app.route('/student_dashboard', methods=['GET', 'POST'])
def student_dashboard():
    if 'user_id' not in session or session.get('role') != 'student':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        complaints_col.insert_one({
            'student_id': session['user_id'],
            'title': title,
            'description': description,
            'status': 'Pending'
        })
        flash('Complaint submitted')
    complaints = list(complaints_col.find({'student_id': session['user_id']}))
    return render_template('student_dashboard.html', complaints=complaints)

@app.route('/faculty_dashboard')
def faculty_dashboard():
    if 'user_id' not in session or session.get('role') != 'faculty':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    # Lookup student usernames for complaints
    complaints = []
    for comp in complaints_col.find().sort('_id', -1):
        student = users_col.find_one({'_id': comp['student_id']})  # But _id is ObjectId, session stores string
        # Fix: store ObjectId for student_id, so convert
        # Let's fix above: convert session['user_id'] and student_id to ObjectId
        from bson.objectid import ObjectId
        student = users_col.find_one({'_id': ObjectId(comp['student_id'])})
        complaints.append({
            'id': str(comp['_id']),
            'title': comp['title'],
            'description': comp['description'],
            'status': comp['status'],
            'student_name': student['username'] if student else 'Unknown'
        })
    return render_template('faculty_dashboard.html', complaints=complaints)

@app.route('/update_status/<complaint_id>', methods=['POST'])
def update_status(complaint_id):
    if 'user_id' not in session or session.get('role') != 'faculty':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    new_status = request.form['status']
    if new_status not in ('Pending', 'In Progress', 'Resolved'):
        flash('Invalid status')
        return redirect(url_for('faculty_dashboard'))
    from bson.objectid import ObjectId
    complaints_col.update_one({'_id': ObjectId(complaint_id)}, {'$set': {'status': new_status}})
    flash('Status updated')
    return redirect(url_for('faculty_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
