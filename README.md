# TextApp - Simple Messaging App

A real-time messaging app built with Flask, Socket.IO, and MongoDB Atlas.

## Features

- 🔐 Account-based authentication (no phone numbers)
- 💬 Real-time messaging with Socket.IO
- 🔍 User search to start new conversations
- 📱 Mobile-responsive design
- ⌨️ Typing indicators

## Local Development

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Set Environment Variables

Create a `.env` file or set these variables:

```bash
# Generate a random secret key
SECRET_KEY=your-secret-key-here

# Your MongoDB Atlas connection string
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/textingapp?retryWrites=true&w=majority
```

### 3. Run the App

```bash
python app.py
```

Visit `http://localhost:5000`

## Deploy to Render

### 1. Create a GitHub Repository

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/textapp.git
git push -u origin main
```

### 2. Deploy on Render

1. Go to [render.com](https://render.com) and sign up/login
2. Click **New +** → **Web Service**
3. Connect your GitHub repository
4. Render will auto-detect the `render.yaml` configuration
5. **Important**: Add your `MONGO_URI` environment variable:
   - Go to **Environment** tab
   - Add `MONGO_URI` with your MongoDB Atlas connection string

### 3. MongoDB Atlas Setup

1. Go to [MongoDB Atlas](https://cloud.mongodb.com)
2. Create a free M0 cluster (if you haven't already)
3. Create a database user:
   - Go to **Database Access** → **Add New Database User**
   - Choose password authentication
   - Give it read/write access
4. Allow network access:
   - Go to **Network Access** → **Add IP Address**
   - Click **Allow Access from Anywhere** (for Render deployment)
5. Get your connection string:
   - Go to **Databases** → **Connect** → **Connect your application**
   - Copy the connection string
   - Replace `<password>` with your database user's password

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Flask session secret (auto-generated on Render) |
| `MONGO_URI` | MongoDB Atlas connection string |

## Tech Stack

- **Backend**: Flask, Flask-SocketIO
- **Database**: MongoDB Atlas
- **Real-time**: Socket.IO
- **Deployment**: Render
- **Authentication**: Flask-Bcrypt

## License

MIT
