from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, emit, join_room
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_mail import Mail, Message
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime, timedelta, UTC
from urllib.parse import quote_plus
import os
import sys
import secrets
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Enable CORS for all domains (needed for Google Sites iframe)
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# Email configuration (set these in Render environment variables)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', os.environ.get('MAIL_USERNAME'))
mail = Mail(app)

# Log email config status (not the actual values for security)
print(f"Email config: SERVER={app.config['MAIL_SERVER']}, PORT={app.config['MAIL_PORT']}")
print(f"Email config: USERNAME={'set' if app.config['MAIL_USERNAME'] else 'NOT SET'}")
print(f"Email config: PASSWORD={'set' if app.config['MAIL_PASSWORD'] else 'NOT SET'}")

# Production settings
IS_PRODUCTION = os.environ.get('RENDER') == 'true'
if IS_PRODUCTION:
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PREFERRED_URL_SCHEME'] = 'https'
else:
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Render handles HTTPS at the load balancer level, no redirect needed
# Just ensure URLs are generated with https scheme in production
if IS_PRODUCTION:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

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
game_saves = db.game_saves  # For Combat Arena game saves

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

# Health check endpoint for server wake-up (no auth required)
@app.route('/api/health')
def health_check():
    return jsonify({'status': 'ok', 'message': 'Server is running'})

# Helper function to send welcome/notification email (non-blocking)
def send_welcome_email(email, display_name, username, deactivate_token):
    # Use app context for background thread
    with app.app_context():
        try:
            # Check if email is configured
            if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
                print("Email credentials not configured - skipping welcome email")
                return False
            
            base_url = os.environ.get('BASE_URL', 'https://textingapp.onrender.com')
            deactivate_link = f"{base_url}/deactivate/{deactivate_token}"
            
            print(f"Sending welcome email to {email}...")
            
            msg = Message(
                'Welcome to TextingApp!',
                recipients=[email]
            )
            msg.body = f"""Hi {display_name},

Welcome to TextingApp! Your account has been created successfully.

Username: {username}

You can now log in and start messaging!

---
DIDN'T CREATE THIS ACCOUNT?
If you didn't create this account, someone may be using your email address without permission.
Click this link to immediately delete the account: {deactivate_link}
"""
            msg.html = f"""
<h2>Welcome to TextingApp!</h2>
<p>Hi {display_name},</p>
<p>Your account has been created successfully.</p>
<p><strong>Username:</strong> {username}</p>
<p>You can now log in and start messaging!</p>
<hr>
<p style="color: #c00; font-size: 14px; margin-top: 20px;"><strong>Didn't create this account?</strong></p>
<p style="color: #666; font-size: 13px;">If you didn't create this account, someone may be using your email address without permission.</p>
<p><a href="{deactivate_link}" style="background-color: #c00; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block;">Delete This Account</a></p>
"""
            mail.send(msg)
            print(f"Welcome email sent to {email}")
            return True
        except Exception as e:
            print(f"Failed to send welcome email: {e}")
            return False

# JSON API Auth endpoints for standalone HTML
@app.route('/api/auth/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    display_name = data.get('display_name', '').strip()
    email = data.get('email', '').strip().lower()
    
    if not username or not password or not email:
        return jsonify({'success': False, 'error': 'Username, email, and password are required'})
    
    if len(username) < 3:
        return jsonify({'success': False, 'error': 'Username must be at least 3 characters'})
    
    if len(password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters'})
    
    # Basic email validation
    if '@' not in email or '.' not in email:
        return jsonify({'success': False, 'error': 'Please enter a valid email address'})
    
    # Check if email already exists
    if users.find_one({'email': email}):
        return jsonify({'success': False, 'error': 'An account with this email already exists'})
    
    if users.find_one({'username': username}):
        return jsonify({'success': False, 'error': 'Username already taken'})
    
    # Generate deactivation token (for email owner to delete account if not theirs)
    deactivate_token = secrets.token_urlsafe(32)
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = {
        'username': username,
        'password': hashed_password,
        'display_name': display_name or username,
        'email': email,
        'deactivate_token': deactivate_token,
        'created_at': datetime.now(UTC),
        'contacts': []
    }
    result = users.insert_one(user)
    
    # Send welcome email in background thread (doesn't block response)
    email_thread = threading.Thread(
        target=send_welcome_email,
        args=(email, user['display_name'], username, deactivate_token)
    )
    email_thread.start()
    
    # Return user immediately - no verification needed
    return jsonify({
        'success': True,
        'user': {
            'id': str(result.inserted_id),
            'username': username,
            'display_name': user['display_name']
        }
    })

@app.route('/api/auth/login', methods=['POST'])
def api_auth_login():
    data = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    
    user = users.find_one({'username': username})
    
    if user and bcrypt.check_password_hash(user['password'], password):
        return jsonify({
            'success': True,
            'user': {
                'id': str(user['_id']),
                'username': user['username'],
                'display_name': user['display_name']
            }
        })
    
    return jsonify({'success': False, 'error': 'Invalid username or password'})

# Email verification endpoint
@app.route('/verify/<token>')
def verify_email(token):
    user = users.find_one({'verification_token': token})
    
    if not user:
        return render_template('verify.html', success=False, message='Invalid verification link')
    
    # Check if token expired
    if user.get('verification_token_expires') and user['verification_token_expires'] < datetime.now(UTC):
        return render_template('verify.html', success=False, message='Verification link has expired. Please request a new one.')
    
    # Mark email as verified
    users.update_one(
        {'_id': user['_id']},
        {
            '$set': {'email_verified': True},
            '$unset': {'verification_token': '', 'verification_token_expires': ''}
        }
    )
    
    return render_template('verify.html', success=True, message='Email verified successfully! You can now log in.')

# API endpoint to resend verification email
@app.route('/api/auth/resend-verification', methods=['POST'])
def resend_verification():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({'success': False, 'error': 'Email is required'})
    
    user = users.find_one({'email': email})
    
    if not user:
        return jsonify({'success': False, 'error': 'No account found with this email'})
    
    if user.get('email_verified'):
        return jsonify({'success': False, 'error': 'Email is already verified'})
    
    # Generate new token
    verification_token = secrets.token_urlsafe(32)
    token_expires = datetime.now(UTC) + timedelta(hours=24)
    
    users.update_one(
        {'_id': user['_id']},
        {
            '$set': {
                'verification_token': verification_token,
                'verification_token_expires': token_expires
            }
        }
    )
    
    if send_verification_email(email, verification_token, user['display_name']):
        return jsonify({'success': True, 'message': 'Verification email sent!'})
    else:
        return jsonify({'success': False, 'error': 'Failed to send email. Please try again later.'})

# Form-based resend verification (for regular templates)
@app.route('/resend-verification', methods=['POST'])
def resend_verification_form():
    email = request.form.get('email', '').strip().lower()
    
    if not email:
        return render_template('login.html', error='Email is required to resend verification')
    
    user = users.find_one({'email': email})
    
    if not user:
        return render_template('login.html', error='No account found with this email')
    
    if user.get('email_verified'):
        return render_template('login.html', error='Email is already verified. You can log in.')
    
    # Generate new token
    verification_token = secrets.token_urlsafe(32)
    token_expires = datetime.now(UTC) + timedelta(hours=24)
    
    users.update_one(
        {'_id': user['_id']},
        {
            '$set': {
                'verification_token': verification_token,
                'verification_token_expires': token_expires
            }
        }
    )
    
    if send_verification_email(email, verification_token, user['display_name']):
        return render_template('login.html', success='Verification email sent! Check your inbox.')
    else:
        return render_template('login.html', error='Failed to send email. Please try again later.')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        display_name = request.form.get('display_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        
        if not username or not password or not email:
            return render_template('register.html', error='Username, email, and password are required')
        
        if len(username) < 3:
            return render_template('register.html', error='Username must be at least 3 characters')
        
        if len(password) < 6:
            return render_template('register.html', error='Password must be at least 6 characters')
        
        if '@' not in email or '.' not in email:
            return render_template('register.html', error='Please enter a valid email address')
        
        # Check if email already exists
        if users.find_one({'email': email}):
            return render_template('register.html', error='An account with this email already exists')
        
        # Check if username exists
        if users.find_one({'username': username}):
            return render_template('register.html', error='Username already taken')
        
        # Generate deactivation token (for email owner to delete account if not theirs)
        deactivate_token = secrets.token_urlsafe(32)
        
        # Create user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = {
            'username': username,
            'password': hashed_password,
            'display_name': display_name or username,
            'email': email,
            'deactivate_token': deactivate_token,
            'created_at': datetime.now(UTC),
            'contacts': []
        }
        result = users.insert_one(user)
        
        # Log user in immediately
        session['user_id'] = str(result.inserted_id)
        session['username'] = username
        session['display_name'] = user['display_name']
        
        # Send welcome email in background thread (doesn't block redirect)
        email_thread = threading.Thread(
            target=send_welcome_email,
            args=(email, user['display_name'], username, deactivate_token)
        )
        email_thread.start()
        
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

# Deactivate account - for email owners who didn't create the account
@app.route('/deactivate/<token>')
def deactivate_account(token):
    user = users.find_one({'deactivate_token': token})
    
    if not user:
        return render_template('deactivate.html', success=False, message='Invalid or expired deactivation link')
    
    user_id = str(user['_id'])
    username = user['username']
    
    # Delete all user's messages
    messages.delete_many({'sender_id': user_id})
    
    # Delete all conversations involving this user
    conversations.delete_many({'participants': user_id})
    
    # Delete the user
    users.delete_one({'_id': user['_id']})
    
    print(f"Account deactivated via email link: {username}")
    
    return render_template('deactivate.html', success=True, 
        message=f'Account "{username}" has been permanently deleted. If you created this account by mistake, you can create a new one.')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ==================== API AUTH ENDPOINTS (for game) ====================
@app.route('/api/login', methods=['POST'])
def api_login():
    """API login for game clients"""
    data = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    
    user = users.find_one({'username': username})
    
    if user and bcrypt.check_password_hash(user['password'], password):
        session['user_id'] = str(user['_id'])
        session['username'] = user['username']
        session['display_name'] = user['display_name']
        return jsonify({
            'success': True,
            'user_id': str(user['_id']),
            'username': user['username'],
            'display_name': user['display_name']
        })
    
    return jsonify({'success': False, 'error': 'Invalid username or password'}), 401

@app.route('/api/register', methods=['POST'])
def api_register():
    """API register for game clients"""
    data = request.get_json()
    username = data.get('username', '').strip().lower()
    display_name = data.get('display_name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    # Validation
    if not username or not display_name or not email or not password:
        return jsonify({'success': False, 'error': 'All fields are required'}), 400
    
    if len(username) < 3:
        return jsonify({'success': False, 'error': 'Username must be at least 3 characters'}), 400
    
    if len(password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
    
    # Check if username or email already exists
    if users.find_one({'username': username}):
        return jsonify({'success': False, 'error': 'Username already taken'}), 400
    
    if users.find_one({'email': email}):
        return jsonify({'success': False, 'error': 'Email already registered'}), 400
    
    # Create user
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    deactivate_token = secrets.token_urlsafe(32)
    
    user_doc = {
        'username': username,
        'display_name': display_name,
        'email': email,
        'password': hashed_password,
        'deactivate_token': deactivate_token,
        'verified': True,  # Auto-verify for game
        'created_at': datetime.now(UTC)
    }
    
    result = users.insert_one(user_doc)
    user_id = str(result.inserted_id)
    
    session['user_id'] = user_id
    session['username'] = username
    session['display_name'] = display_name
    
    return jsonify({
        'success': True,
        'user_id': user_id,
        'username': username,
        'display_name': display_name
    })

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html', 
                         username=session['username'],
                         display_name=session['display_name'])

@app.route('/game')
def game():
    """Serve the Combat Arena game"""
    return render_template('game.html')

@app.route('/api/search_users')
def search_users():
    # Support both session and user_id parameter
    user_id = session.get('user_id') or request.args.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    query = request.args.get('q', '').strip().lower()
    
    # Search users by username (exclude current user)
    if query:
        found_users = users.find({
            'username': {'$regex': query, '$options': 'i'},
            '_id': {'$ne': ObjectId(user_id)}
        }).limit(10)
    else:
        # If no query, return all users (up to 20)
        found_users = users.find({
            '_id': {'$ne': ObjectId(user_id)}
        }).limit(20)
    
    return jsonify([{
        'id': str(u['_id']),
        'username': u['username'],
        'display_name': u['display_name']
    } for u in found_users])

@app.route('/api/conversations')
def get_conversations():
    # Support both session and user_id parameter
    user_id = session.get('user_id') or request.args.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Get all conversations for user
    user_convos = conversations.find({
        'participants': user_id
    }).sort('last_message_at', -1)
    
    result = []
    for convo in user_convos:
        is_group = convo.get('is_group', False)
        
        if is_group:
            # Group chat - get all participants except current user for display
            participant_ids = [p for p in convo['participants'] if p != user_id]
            participants_info = []
            for pid in participant_ids[:5]:  # Limit to 5 for display
                p_user = users.find_one({'_id': ObjectId(pid)})
                if p_user:
                    participants_info.append({
                        'id': str(p_user['_id']),
                        'username': p_user['username'],
                        'display_name': p_user['display_name']
                    })
            
            result.append({
                'id': str(convo['_id']),
                'is_group': True,
                'group_name': convo.get('group_name', 'Group Chat'),
                'participants': participants_info,
                'participant_count': len(convo['participants']),
                'last_message': convo.get('last_message', ''),
                'last_message_at': convo.get('last_message_at', '').isoformat() if convo.get('last_message_at') else None,
                'unread_count': convo.get(f'unread_{user_id}', 0)
            })
        else:
            # Direct message - get the other participant
            other_id = [p for p in convo['participants'] if p != user_id][0]
            other_user = users.find_one({'_id': ObjectId(other_id)})
            
            if other_user:
                result.append({
                    'id': str(convo['_id']),
                    'is_group': False,
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
    # Support both session and user_id parameter
    user_id = session.get('user_id') or request.args.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
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
    
    # Build response with sender names
    result = []
    sender_cache = {}
    for m in msgs:
        sender_id = m['sender_id']
        # Cache sender names to avoid repeated lookups
        if sender_id not in sender_cache:
            sender = users.find_one({'_id': ObjectId(sender_id)})
            sender_cache[sender_id] = sender['display_name'] if sender else 'Unknown'
        
        result.append({
            'id': str(m['_id']),
            'sender_id': sender_id,
            'sender_name': sender_cache[sender_id],
            'content': m['content'],
            'created_at': m['created_at'].isoformat()
        })
    
    return jsonify(result)

@app.route('/api/start_conversation', methods=['POST'])
def start_conversation():
    data = request.get_json()
    
    # Support both session and current_user_id parameter
    user_id = session.get('user_id') or data.get('current_user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    other_user_id = data.get('user_id')
    
    if not other_user_id:
        return jsonify({'error': 'User ID required'}), 400
    
    # Check if conversation already exists (only for 1-on-1)
    existing = conversations.find_one({
        'participants': {'$all': [user_id, other_user_id], '$size': 2},
        'is_group': {'$ne': True}
    })
    
    if existing:
        return jsonify({'conversation_id': str(existing['_id'])})
    
    # Create new conversation
    convo = {
        'participants': [user_id, other_user_id],
        'is_group': False,
        'created_at': datetime.now(UTC),
        'last_message_at': datetime.now(UTC),
        'last_message': '',
        f'unread_{user_id}': 0,
        f'unread_{other_user_id}': 0
    }
    result = conversations.insert_one(convo)
    
    return jsonify({'conversation_id': str(result.inserted_id)})

@app.route('/api/create_group', methods=['POST'])
def create_group():
    data = request.get_json()
    
    # Support both session and current_user_id parameter
    user_id = session.get('user_id') or data.get('current_user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    group_name = data.get('group_name', '').strip()
    member_ids = data.get('member_ids', [])
    
    if not group_name:
        return jsonify({'error': 'Group name is required'}), 400
    
    if len(member_ids) < 1:
        return jsonify({'error': 'Add at least one other member'}), 400
    
    # Add current user to participants
    all_participants = [user_id] + member_ids
    
    # Create unread counters for all participants
    unread_fields = {f'unread_{p}': 0 for p in all_participants}
    
    # Create new group conversation
    convo = {
        'participants': all_participants,
        'is_group': True,
        'group_name': group_name,
        'created_by': user_id,
        'created_at': datetime.now(UTC),
        'last_message_at': datetime.now(UTC),
        'last_message': '',
        **unread_fields
    }
    result = conversations.insert_one(convo)
    
    return jsonify({
        'success': True,
        'conversation_id': str(result.inserted_id),
        'group_name': group_name
    })

# Socket.IO events
@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        join_room(session['user_id'])
        print(f"User {session['username']} connected")

@socketio.on('authenticate')
def handle_authenticate(data):
    user_id = data.get('user_id')
    if user_id:
        join_room(user_id)
        print(f"User {user_id} authenticated via standalone")

@socketio.on('join_conversation')
def handle_join(data):
    conversation_id = data.get('conversation_id')
    if conversation_id:
        join_room(conversation_id)

@socketio.on('send_message')
def handle_message(data):
    # Support both session and sender_id from data
    user_id = session.get('user_id') or data.get('sender_id')
    if not user_id:
        return
    
    conversation_id = data.get('conversation_id')
    content = data.get('content', '').strip()
    
    if not conversation_id or not content:
        return
    
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
        'created_at': datetime.now(UTC)
    }
    result = messages.insert_one(message)
    
    # Update conversation - increment unread for all other participants
    other_ids = [p for p in convo['participants'] if p != user_id]
    update_inc = {f'unread_{oid}': 1 for oid in other_ids}
    
    conversations.update_one(
        {'_id': ObjectId(conversation_id)},
        {
            '$set': {
                'last_message': content[:50],
                'last_message_at': datetime.now(UTC)
            },
            '$inc': update_inc
        }
    )
    
    # Broadcast message to conversation room
    # Get display name from session or lookup user
    sender_name = session.get('display_name')
    if not sender_name:
        sender_user = users.find_one({'_id': ObjectId(user_id)})
        sender_name = sender_user['display_name'] if sender_user else 'Unknown'
    
    emit('new_message', {
        'id': str(result.inserted_id),
        'conversation_id': conversation_id,
        'sender_id': user_id,
        'sender_name': sender_name,
        'content': content,
        'created_at': datetime.now(UTC).isoformat()
    }, room=conversation_id)
    
    # Notify all other participants
    for other_id in other_ids:
        emit('conversation_updated', {
            'conversation_id': conversation_id
        }, room=other_id)

@socketio.on('typing')
def handle_typing(data):
    user_id = session.get('user_id') or data.get('user_id')
    if user_id:
        conversation_id = data.get('conversation_id')
        if conversation_id:
            # Get display name
            display_name = session.get('display_name')
            if not display_name:
                user = users.find_one({'_id': ObjectId(user_id)})
                display_name = user['display_name'] if user else 'Someone'
            
            emit('user_typing', {
                'user_id': user_id,
                'username': display_name
            }, room=conversation_id, include_self=False)

# ==================== COMBAT ARENA GAME API ====================

@app.route('/api/game/save', methods=['POST'])
def save_game():
    """Save game state for a user"""
    data = request.get_json()
    user_id = session.get('user_id') or data.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    game_data = data.get('game_data', {})
    
    # Upsert game save (one save per user)
    game_saves.update_one(
        {'user_id': user_id},
        {
            '$set': {
                'user_id': user_id,
                'game_data': game_data,
                'updated_at': datetime.now(UTC)
            },
            '$setOnInsert': {
                'created_at': datetime.now(UTC)
            }
        },
        upsert=True
    )
    
    return jsonify({'success': True, 'message': 'Game saved'})

@app.route('/api/game/load')
def load_game():
    """Load game state for a user"""
    user_id = session.get('user_id') or request.args.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    save = game_saves.find_one({'user_id': user_id})
    
    if save:
        return jsonify({
            'success': True,
            'game_data': save.get('game_data', {}),
            'updated_at': save.get('updated_at').isoformat() if save.get('updated_at') else None
        })
    else:
        return jsonify({
            'success': True,
            'game_data': None,
            'message': 'No save found'
        })

@app.route('/api/game/delete', methods=['POST'])
def delete_game_save():
    """Delete game save for a user"""
    data = request.get_json() or {}
    user_id = session.get('user_id') or data.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    result = game_saves.delete_one({'user_id': user_id})
    
    return jsonify({
        'success': True,
        'deleted': result.deleted_count > 0
    })

@app.route('/api/game/leaderboard')
def get_leaderboard():
    """Get top players by highest wave reached"""
    # Get top 50 saves by highest wave
    top_saves = game_saves.find({
        'game_data.highestWaveReached': {'$exists': True}
    }).sort('game_data.highestWaveReached', -1).limit(50)
    
    leaderboard = []
    for save in top_saves:
        user = users.find_one({'_id': ObjectId(save['user_id'])})
        if user:
            leaderboard.append({
                'display_name': user.get('display_name', 'Unknown'),
                'highest_wave': save.get('game_data', {}).get('highestWaveReached', 1),
                'coins': save.get('game_data', {}).get('coins', 0),
                'total_kills': save.get('game_data', {}).get('totalKills', 0)
            })
    
    return jsonify(leaderboard)

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True, use_reloader=False)
