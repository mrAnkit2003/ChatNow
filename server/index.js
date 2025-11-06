import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import mongoose from 'mongoose';
import 'dotenv/config';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// --- App & Server Setup ---
const app = express();
const server = createServer(app);

// --- *** NEW: Production-Ready URLs *** ---
// We'll get the client URL from an environment variable
// Fallback to localhost for development
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:5173';

app.use(cors({
  origin: CLIENT_URL, // Use the variable here
  methods: ["GET", "POST"]
}));
app.use(express.json());

// --- Database Connection ---
const MONGO_URI = process.env.MONGO_URI;
mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB connected successfully.'))
  .catch((err) => console.error('MongoDB connection error:', err));

// --- Database Schemas (Unchanged) ---
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

const messageSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  senderUsername: { type: String, required: true },
  recipientUsername: { type: String, required: true },
});
const Message = mongoose.model('Message', messageSchema);

// --- Auth Middleware (Unchanged) ---
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.status(403).json({ message: "A token is required for authentication" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
  } catch (err) {
    return res.status(401).json({ message: "Invalid Token" });
  }
  return next();
};

// --- API Endpoints (Unchanged) ---
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required." });
    }
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "Username already taken." });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "User created successfully!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required." });
    }
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials." });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials." });
    }
    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '3h' }
    );
    res.status(200).json({
      message: "Login successful!",
      token: token,
      user: { id: user._id, username: user.username }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get('/api/users', verifyToken, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.user.id } }).select('username _id');
    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get('/api/messages/:otherUserId', verifyToken, async (req, res) => {
  try {
    const myId = req.user.id;
    const otherUserId = req.params.otherUserId;
    const messages = await Message.find({
      $or: [
        { senderId: myId, recipientId: otherUserId },
        { senderId: otherUserId, recipientId: myId }
      ]
    }).sort({ timestamp: 1 });
    res.json(messages);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


// --- Socket.io Logic ---
const userSocketMap = new Map();

const io = new Server(server, {
  cors: {
    origin: CLIENT_URL, // Use the variable here
    methods: ["GET", "POST"]
  }
});

function broadcastOnlineUsers() {
  const onlineUserIds = Array.from(userSocketMap.keys());
  io.emit('online_users', onlineUserIds);
  console.log('Broadcasted online users:', onlineUserIds);
}

io.on('connection', (socket) => {
  console.log(`A user connected: ${socket.id}`);

  socket.on('authenticate', (token) => {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const userId = decoded.id;
      userSocketMap.set(userId, socket.id);
      console.log(`User ${decoded.username} (${userId}) authenticated with socket ${socket.id}`);
      broadcastOnlineUsers();
    } catch (err) {
      console.log(`Socket ${socket.id} authentication failed.`);
      socket.disconnect();
    }
  });

  socket.on('send_message', async ({ token, text, recipientId }) => {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const senderId = decoded.id;
      const senderUsername = decoded.username;
      const recipient = await User.findById(recipientId);
      if (!recipient) {
        throw new Error("Recipient not found");
      }
      const newMessage = new Message({
        senderId,
        recipientId,
        text,
        senderUsername: senderUsername,
        recipientUsername: recipient.username
      });
      await newMessage.save();
      const recipientSocketId = userSocketMap.get(recipientId);
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('receive_message', newMessage);
      }
      socket.emit('receive_message', newMessage);
    } catch (err) {
      console.error('Error sending message:', err.message);
    }
  });

  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.id}`);
    let disconnectedUserId = null;
    for (let [userId, socketId] of userSocketMap.entries()) {
      if (socketId === socket.id) {
        disconnectedUserId = userId;
        break;
      }
    }
    if (disconnectedUserId) {
      userSocketMap.delete(disconnectedUserId);
      console.log(`User ${disconnectedUserId} removed from map.`);
      broadcastOnlineUsers();
    }
  });
});

// --- Start Server ---
// --- *** NEW: Production-Ready Port *** ---
// Render will give us a PORT environment variable.
const PORT = process.env.PORT || 5001;
server.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});