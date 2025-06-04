const express = require('express');
const http = require('http');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
  },
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'ton_secret_jwt';
const mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/chatapp';

mongoose.connect(mongoUri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  passwordHash: String,
});

const messageSchema = new mongoose.Schema({
  sender: String,
  receiver: String,
  content: String,
  timestamp: Date,
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

app.use(cors());
app.use(express.json());

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const passwordHash = await bcrypt.hash(password, 10);
  try {
    const user = new User({ username, passwordHash });
    await user.save();
    res.status(201).send({ message: 'Utilisateur créé' });
  } catch (err) {
    res.status(400).send({ error: 'Nom d\'utilisateur déjà pris' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(400).send({ error: 'Utilisateur non trouvé' });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(400).send({ error: 'Mot de passe incorrect' });

  const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET);
  res.send({ token });
});

const authenticate = (socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Auth error'));

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return next(new Error('Auth error'));
    socket.user = decoded;
    next();
  });
};

io.use(authenticate);

io.on('connection', (socket) => {
  console.log('Utilisateur connecté:', socket.user.username);

  socket.on('private_message', async ({ content, to }) => {
    const message = new Message({
      sender: socket.user.username,
      receiver: to,
      content,
      timestamp: new Date(),
    });
    await message.save();

    const clients = Array.from(io.sockets.sockets.values());
    clients.forEach((client) => {
      if (client.user.username === to) {
        client.emit('private_message', {
          content,
          from: socket.user.username,
          timestamp: message.timestamp,
        });
      }
    });
  });
});

server.listen(PORT, () => {
  console.log(`Serveur lancé sur le port ${PORT}`);
});
