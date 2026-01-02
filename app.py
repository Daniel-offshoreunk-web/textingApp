from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, emit, join_room
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime, UTC
from urllib.parse import quote_plus
import os
import sys

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Production settings
IS_PRODUCTION = os.environ.get('RENDER') == 'true'
if IS_PRODUCTION:
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PREFERRED_URL_SCHEME'] = 'https'
else:
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Force HTTPS in production
@app.before_request
def force_https():
    if IS_PRODUCTION and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

# MongoDB Atlas connection - use environment variable in production
MONGO_URI = os.environ.get('MONGO_URI')
if not MONGO_URI:
    # Local development fallback
    username = "offshoreunk_db_user"
    password = quote_plus("4*X)%tXvjTP6x.(")
    MONGO_URI = f"mongodb+srv://{username}:{password}@gamedatacluster.wkvybzi.mongodb.net/textingapp?retryWrites=true&w=majority"

print("Connecting to MongoDB Atlas...")
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    print("Connected to MongoDB Atlas successfully!")
except Exception as e:
    print(f"Failed to connect to MongoDB: {e}")
    sys.exit(1)

db = client['textingapp']

# Collections
users = db.users
messages = db.messages
conversations = db.conversations

bcrypt = Bcrypt(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Helper function to serialize MongoDB documents
def serialize_doc(doc):
    if doc:
        doc['_id'] = str(doc['_id'])
    return doc

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        display_name = request.form.get('display_name', '').strip()
        
        if not username or not password:
            return render_template('register.html', error='Username and password are required')
        
        if len(username) < 3:
            return render_template('register.html', error='Username must be at least 3 characters')
        
        if len(password) < 6:
            return render_template('register.html', error='Password must be at least 6 characters')
        
        # Check if username exists
        if users.find_one({'username': username}):
            return render_template('register.html', error='Username already taken')
        
        # Create user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = {
            'username': username,
            'password': hashed_password,
            'display_name': display_name or username,
            'created_at': datetime.utcnow(),
            'contacts': []
        }
        result = users.insert_one(user)
        
        session['user_id'] = str(result.inserted_id)
        session['username'] = username
        session['display_name'] = user['display_name']
        
        return redirect(url_for('chat'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        
        user = users.find_one({'username': username})
        
        if user and bcrypt.check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            session['display_name'] = user['display_name']
            return redirect(url_for('chat'))
        
        return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html', 
                         username=session['username'],
                         display_name=session['display_name'])

@app.route('/api/search_users')
def search_users():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    query = request.args.get('q', '').strip().lower()
    if len(query) < 2:
        return jsonify([])
    
    # Search users by username (exclude current user)
    found_users = users.find({
        'username': {'$regex': query, '$options': 'i'},
        '_id': {'$ne': ObjectId(session['user_id'])}
    }).limit(10)
    
    return jsonify([{
        'id': str(u['_id']),
        'username': u['username'],
        'display_name': u['display_name']
    } for u in found_users])

@app.route('/api/conversations')
def get_conversations():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    # Get all conversations for user
    user_convos = conversations.find({
        'participants': user_id
    }).sort('last_message_at', -1)
    
    result = []
    for convo in user_convos:
        # Get the other participant
        other_id = [p for p in convo['participants'] if p != user_id][0]
        other_user = users.find_one({'_id': ObjectId(other_id)})
        
        if other_user:
            result.append({
                'id': str(convo['_id']),
                'participant': {
                    'id': str(other_user['_id']),
                    'username': other_user['username'],
                    'display_name': other_user['display_name']
                },
                'last_message': convo.get('last_message', ''),
                'last_message_at': convo.get('last_message_at', '').isoformat() if convo.get('last_message_at') else None,
                'unread_count': convo.get(f'unread_{user_id}', 0)
            })
    
    return jsonify(result)

@app.route('/api/messages/<conversation_id>')
def get_messages(conversation_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    # Verify user is part of conversation
    convo = conversations.find_one({
        '_id': ObjectId(conversation_id),
        'participants': user_id
    })
    
    if not convo:
        return jsonify({'error': 'Conversation not found'}), 404
    
    # Mark as read
    conversations.update_one(
        {'_id': ObjectId(conversation_id)},
        {'$set': {f'unread_{user_id}': 0}}
    )
    
    # Get messages
    msgs = messages.find({
        'conversation_id': conversation_id
    }).sort('created_at', 1).limit(100)
    
    return jsonify([{
        'id': str(m['_id']),
        'sender_id': m['sender_id'],
        'content': m['content'],
        'created_at': m['created_at'].isoformat()
    } for m in msgs])

@app.route('/api/start_conversation', methods=['POST'])
def start_conversation():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    other_user_id = data.get('user_id')
    
    if not other_user_id:
        return jsonify({'error': 'User ID required'}), 400
    
    user_id = session['user_id']
    
    # Check if conversation already exists
    existing = conversations.find_one({
        'participants': {'$all': [user_id, other_user_id]}
    })
    
    if existing:
        return jsonify({'conversation_id': str(existing['_id'])})
    
    # Create new conversation
    convo = {
        'participants': [user_id, other_user_id],
        'created_at': datetime.utcnow(),
        'last_message_at': datetime.utcnow(),
        'last_message': '',
        f'unread_{user_id}': 0,
        f'unread_{other_user_id}': 0
    }
    result = conversations.insert_one(convo)
    
    return jsonify({'conversation_id': str(result.inserted_id)})

# Socket.IO events
@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        join_room(session['user_id'])
        print(f"User {session['username']} connected")

@socketio.on('join_conversation')
def handle_join(data):
    conversation_id = data.get('conversation_id')
    if conversation_id:
        join_room(conversation_id)

@socketio.on('send_message')
def handle_message(data):
    if 'user_id' not in session:
        return
    
    conversation_id = data.get('conversation_id')
    content = data.get('content', '').strip()
    
    if not conversation_id or not content:
        return
    
    user_id = session['user_id']
    
    # Verify user is in conversation
    convo = conversations.find_one({
        '_id': ObjectId(conversation_id),
        'participants': user_id
    })
    
    if not convo:
        return
    
    # Save message
    message = {
        'conversation_id': conversation_id,
        'sender_id': user_id,
        'content': content,
        'created_at': datetime.utcnow()
    }
    result = messages.insert_one(message)
    
    # Update conversation
    other_id = [p for p in convo['participants'] if p != user_id][0]
    conversations.update_one(
        {'_id': ObjectId(conversation_id)},
        {
            '$set': {
                'last_message': content[:50],
                'last_message_at': datetime.utcnow()
            },
            '$inc': {f'unread_{other_id}': 1}
        }
    )
    
    # Broadcast message to conversation room
    emit('new_message', {
        'id': str(result.inserted_id),
        'conversation_id': conversation_id,
        'sender_id': user_id,
        'sender_name': session['display_name'],
        'content': content,
        'created_at': datetime.utcnow().isoformat()
    }, room=conversation_id)
    
    # Notify other user
    emit('conversation_updated', {
        'conversation_id': conversation_id
    }, room=other_id)

@socketio.on('typing')
def handle_typing(data):
    if 'user_id' in session:
        conversation_id = data.get('conversation_id')
        if conversation_id:
            emit('user_typing', {
                'user_id': session['user_id'],
                'username': session['display_name']
            }, room=conversation_id, include_self=False)

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True, use_reloader=False)
