import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import mongoose from 'mongoose';
import 'dotenv/config';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v2 as cloudinary } from 'cloudinary'; 

// --- App & Server Setup ---
const app = express();
const server = createServer(app);

// --- *** NEW: Configure Cloudinary *** ---
// This uses the new variables from your .env file
cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET 
});

// --- *** NEW: Increase body limit for image data URLs *** ---
// We need this to send the image data from the client to the server
app.use(express.json({ limit: '50mb' })); 
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// --- Production-Ready URLs ---
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:5173';
app.use(cors({
  origin: CLIENT_URL,
  methods: ["GET", "POST"]
}));

// --- Database Connection ---
const MONGO_URI = process.env.MONGO_URI;
mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB connected successfully.'))
  .catch((err) => console.error('MongoDB connection error:', err));

// --- Database Schemas ---
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  // --- *** NEW: Add avatarUrl field *** ---
  avatarUrl: { type: String, default: '' } // Will store the URL from Cloudinary
});
const User = mongoose.model('User', userSchema);

// (Message Schema is unchanged)
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

// --- API Endpoints ---
app.post('/register', async (req, res) => {
  // (This endpoint is unchanged)
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
      user: { 
        id: user._id, 
        username: user.username,
        // --- *** NEW: Send avatarUrl on login *** ---
        avatarUrl: user.avatarUrl 
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get('/api/users', verifyToken, async (req, res) => {
  try {
    // --- *** NEW: Also select the avatarUrl *** ---
    const users = await User.find({ _id: { $ne: req.user.id } }).select('username _id avatarUrl');
    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get('/api/messages/:otherUserId', verifyToken, async (req, res) => {
  // (This endpoint is unchanged)
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

// --- *** NEW: API Endpoint for Avatar Upload *** ---
app.post('/api/upload-avatar', verifyToken, async (req, res) => {
  try {
    const { dataUrl } = req.body; // We'll send the image as a Data URL string
    if (!dataUrl) {
      return res.status(400).json({ message: "No image data provided." });
    }

    // Upload to Cloudinary
    const result = await cloudinary.uploader.upload(dataUrl, {
      folder: "chatnow_avatars", // A folder to keep things organized
      public_id: req.user.id,     // Use the user's ID as a unique filename
      overwrite: true,            // Replace the old image if one exists
      transformation: [           // Auto-crop to a square
        {width: 200, height: 200, gravity: "face", crop: "fill"}
      ]
    });

    const avatarUrl = result.secure_url; // Get the URL from Cloudinary

    // Update user in our database
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { avatarUrl },
      { new: true } // Return the updated document
    ).select('-password'); // Don't send the password back!

    res.status(200).json({ 
      message: "Avatar updated!", 
      user: updatedUser // Send back the full updated user object
    });
  } catch (err) {
    console.error('Error uploading avatar:', err);
    res.status(500).json({ message: "Server error during upload." });
  }
});


// --- Socket.io Logic (Unchanged) ---
const userSocketMap = new Map();
const io = new Server(server, {
  cors: { origin: CLIENT_URL, methods: ["GET", "POST"] }
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
      if (!recipient) throw new Error("Recipient not found");
      
      const newMessage = new Message({
        senderId, recipientId, text,
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
const PORT = process.env.PORT || 5001;
server.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});



