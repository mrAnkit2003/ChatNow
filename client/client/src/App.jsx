import { useState, useEffect, createContext, useContext, useRef } from 'react';
import { io } from 'socket.io-client';
import './App.css'; 

// --- *** NEW: Production-Ready URL *** ---
// We'll get the server URL from a Vite environment variable
// Fallback to localhost for development
const SERVER_URL = import.meta.env.VITE_SERVER_URL || 'http://localhost:5001';

// --- 1. SETUP SOCKET & AUTH CONTEXT ---
const socket = io(SERVER_URL); // <-- 1. FIX HERE
const AuthContext = createContext();

function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);

  useEffect(() => {
    const storedUser = localStorage.getItem('chatUser');
    const storedToken = localStorage.getItem('chatToken');
    if (storedUser && storedToken) {
      const parsedUser = JSON.parse(storedUser);
      setUser(parsedUser);
      setToken(storedToken);
      socket.emit('authenticate', storedToken);
    }
  }, []);

  const login = (userData, userToken) => {
    setUser(userData);
    setToken(userToken);
    localStorage.setItem('chatUser', JSON.stringify(userData));
    localStorage.setItem('chatToken', userToken);
    socket.emit('authenticate', userToken);
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('chatUser');
    localStorage.removeItem('chatToken');
    // The server 'disconnect' event will handle cleaning up the socket map
  };

  return (
    <AuthContext.Provider value={{ user, token, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

const useAuth = () => {
  return useContext(AuthContext);
};

// --- 2. THE MAIN APP ---
function App() {
  return (
    <AuthProvider>
      <div className="App">
        <header className="App-header">
          <AppContent />
        </header>
      </div>
    </AuthProvider>
  );
}

// --- 3. APP CONTENT (Handles auth state) ---
function AppContent() {
  const { user } = useAuth();
  return user ? <ChatPage /> : <AuthPage />;
}

// --- 4. AUTH PAGE (Login/Register) ---
function AuthPage() {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setMessage('');
    if (!username || !password) {
      setError("Username and password are required.");
      return;
    }
    const endpoint = isLogin ? '/login' : '/register';
    const url = `${SERVER_URL}${endpoint}`; // <-- 2. FIX HERE
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || "Something went wrong");
      }
      if (isLogin) {
        login(data.user, data.token);
      } else {
        setMessage("Registration successful! Please login.");
        setIsLogin(true);
      }
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="auth-container">
      <form className="auth-form" onSubmit={handleSubmit}>
        <h2>{isLogin ? 'Login' : 'Register'}</h2>
        {error && <p className="auth-error">{error}</p>}
        {message && <p className="status-on">{message}</p>}
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <button type="submit">{isLogin ? 'Login' : 'Register'}</button>
        <button
          type="button"
          className="auth-toggle"
          onClick={() => setIsLogin(!isLogin)}
        >
          {isLogin ? 'Need an account? Register' : 'Have an account? Login'}
        </button>
      </form>
    </div>
  );
}


// --- 5. CHAT PAGE (With Online Status Added) ---
function ChatPage() {
  const [isConnected, setIsConnected] = useState(socket.connected);
  const [message, setMessage] = useState('');
  const [messages, setMessages] = useState([]);
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  
  const [onlineUsers, setOnlineUsers] = useState([]);
  
  const { user, token, logout } = useAuth();
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };
  useEffect(scrollToBottom, [messages]);

  // Fetch all users
  useEffect(() => {
    async function fetchUsers() {
      try {
        const response = await fetch(`${SERVER_URL}/api/users`, { // <-- 3. FIX HERE
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!response.ok) {
          throw new Error('Failed to fetch users');
        }
        const data = await response.json();
        setUsers(data);
      } catch (err) {
        console.error(err.message);
      }
    }
    if (token) {
      fetchUsers();
    }
  }, [token]);

  // Fetch message history
  useEffect(() => {
    if (selectedUser) {
      async function fetchMessages() {
        try {
          const response = await fetch(`${SERVER_URL}/api/messages/${selectedUser._id}`, { // <-- 4. FIX HERE
            headers: { 'Authorization': `Bearer ${token}` }
          });
          if (!response.ok) {
            throw new Error('Failed to fetch messages');
          }
          const data = await response.json();
          setMessages(data);
        } catch (err) {
          console.error(err.message);
        }
      }
      fetchMessages();
    }
  }, [selectedUser, token]);


  // Main effect for socket listeners
  useEffect(() => {
    function onConnect() {
      setIsConnected(true);
      if (token) {
        socket.emit('authenticate', token);
      }
    }
    function onDisconnect() {
      setIsConnected(false);
    }
    
    function onReceiveMessage(data) {
      if (selectedUser) {
        if (data.senderId === selectedUser._id || data.recipientId === selectedUser._id) {
          setMessages(prevMessages => [...prevMessages, data]);
        }
      }
    }
    
    function onOnlineUsers(onlineUserIds) {
      setOnlineUsers(onlineUserIds);
    }
    
    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('receive_message', onReceiveMessage);
    socket.on('online_users', onOnlineUsers);

    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('receive_message', onReceiveMessage);
      socket.off('online_users', onOnlineUsers);
    };
  }, [selectedUser, token]); 

  const sendMessage = (e) => {
    e.preventDefault();
    if (message.trim() && selectedUser) { 
      const messageData = {
        token: token, 
        text: message,
        recipientId: selectedUser._id
      };
      socket.emit('send_message', messageData);
      setMessage('');
    }
  };

  return (
    <>
      <div className="header-bar">
        <h1>ChatNow</h1>
        <p>
          Server:
          {isConnected ? (
            <span className="status-on">Connected</span>
          ) : (
            <span className="status-off">Disconnected</span>
          )}
        </p>
        <span className="welcome-user">Welcome, {user.username}!</span>
        <button className="logout-button" onClick={logout}>Logout</button>
      </div>
      
      <div className="chat-layout">

        <div className="user-list">
          <h2>Users</h2>
          {users.map((u) => (
            <div
              key={u._id}
              className={`user-item ${selectedUser?._id === u._id ? 'selected' : ''}`}
              onClick={() => setSelectedUser(u)}
            >
              <span className="username-span">{u.username}</span>
              {onlineUsers.includes(u._id) && (
                <span className="online-indicator"></span>
              )}
            </div>
          ))}
        </div>

        <div className="chat-window">
          {selectedUser ? (
            <>
              <div className="chat-header">
                <h3>Chat with {selectedUser.username}</h3>
              </div>
              <div className="message-list">
                {messages.map((msg, index) => (
                  <div 
                    key={msg._id || index}
                    className={`message ${msg.senderId === user.id ? 'mine' : 'theirs'}`}
                  >
                    <span className="message-author">{msg.senderUsername}</span>
                    <span className="message-text">{msg.text}</span>
                  </div>
                ))}
                <div ref={messagesEndRef} />
              </div>
              <form className="message-form" onSubmit={sendMessage}>
                <input
                  type="text"
                  value={message}
                  onChange={(e) => setMessage(e.target.value)} // <-- SYNTAX ERROR FIXED HERE
                  placeholder={`Message ${selectedUser.username}...`}
                />
                <button type="submit">Send</button>
              </form>
            </>
          ) : (
            <div className="no-chat-selected">
              <h2>Select a user to start chatting</h2>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

export default App;
