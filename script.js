require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

// Connect to MongoDB using environment variable
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

// User Schema
const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    tasks: [String],
    chatHistory: [{ sender: String, message: String, timestamp: Date }],
});

const User = mongoose.model('User ', UserSchema); // Removed extra space

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Register a new user
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword });
        await user.save();
        res.status(201).send({ message: 'User  registered successfully' });
    } catch (error) {
        console.error('Registration error:', error);
        if (error.code === 11000) { // Duplicate username error
            return res.status(400).send({ message: 'Username already exists' });
        }
        res.status(500).send({ message: 'Error registering user' });
    }
});

// Login user
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).send({ message: 'Invalid credentials: User not found' });
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).send({ message: 'Invalid credentials: Incorrect password' });
        }
        // Generate a token without a secret key (not recommended)
        const token = jwt.sign({ id: user._id }, 'dummy_secret_key', { expiresIn: '1h' });
        res.send({ token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).send({ message: 'Error logging in' });
    }
});

// Middleware to authenticate JWT
const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization'];
    if (token) {
        // Verify the token with a dummy secret key (not recommended)
        jwt.verify(token, 'dummy_secret_key', (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
};

// Get user profile
app.get('/api/profile', authenticateJWT, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            return res.status(404).send({ message: 'User  not found' });
        }
        res.send(user);
    } catch (error) {
        console.error('Profile retrieval error:', error);
        res.status(500).send({ message: 'Error retrieving profile' });
    }
});

// Add a task
app.post('/api/tasks', authenticateJWT, async (req, res) => {
    const { task } = req.body;
    try {
        await User.findByIdAndUpdate(req.user.id, { $push: { tasks: task } });
        res.send({ message: 'Task added successfully' });
    } catch (error) {
        console.error('Error adding task:', error);
        res.status(500).send({ message: 'Error adding task' });
    }
});

// Get user tasks
app.get('/api/tasks', authenticateJWT, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('tasks');
        res.send(user.tasks);
    } catch (error) {
        console.error('Error retrieving tasks:', error);
        res.status(500).send({ message: 'Error retrieving tasks' });
    }
});

// Search tasks
app.get('/api/search', authenticateJWT, async (req, res) => {
    const { query } = req.query;
    try {
        const user = await User.findById(req.user.id);
        const results = user.tasks.filter(task => task.toLowerCase().includes(query.toLowerCase()));
        res.send(results);
    } catch (error) {
        console.error('Error searching tasks:', error);
        res.status(500).send({ message: 'Error searching tasks' });
    }
});

// Send a chat message
app.post('/api/chat', authenticateJWT, async (req, res) => {
    const { message } = req.body;
    try {
        const chatEntry = {
            sender: req.user.id,
            message,
            timestamp: new Date(),
        };
        await User.findByIdAndUpdate(req.user.id, { $push: { chatHistory: chatEntry } });
        res.send({ message: 'Chat message sent successfully' });
    } catch (error) {
        console.error('Error sending chat message:', error);
        res.status(500).send({ message: 'Error sending chat message' });
    }
});

// Get chat history
app.get('/api/chat', authenticateJWT, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('chatHistory');
        res.send(user.chatHistory);
    } catch (error) {
        console.error('Error retrieving chat history:', error);
        res.status(500).send({ message: 'Error retrieving chat history' });
    }
});

// Get leaderboard (users with the most tasks)
app.get('/api/leaderboard', async (req, res) => {
    try {
        const users = await User.find().select('username tasks').sort({ 'tasks.length': -1 }).limit(10);
        const leaderboard = users.map(user => ({
            username: user.username,
            taskCount: user.tasks.length,
        }));
        res.send(leaderboard);
    } catch (error) {
        console.error('Error retrieving leaderboard:', error);
        res.status(500).send({ message: 'Error retrieving leaderboard' });
    }
});

// Start the server
const PORT = process.env.PORT || 27017;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});