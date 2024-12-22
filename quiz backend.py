const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MongoDB Connection
mongoose
    .connect("mongodb://localhost:27017/quiz-app", { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("MongoDB connected"))
    .catch((err) => console.log("Database connection error:", err));

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

// Quiz Schema
const quizSchema = new mongoose.Schema({
    question: String,
    choices: [String],
    correct: Number,
});

const Quiz = mongoose.model("Quiz", quizSchema);

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const token = req.headers["authorization"];
    if (!token) return res.status(401).json({ message: "Access Denied" });

    jwt.verify(token, "secret_key", (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid Token" });
        req.user = user;
        next();
    });
};

// Routes

// User Registration
app.post("/register", async (req, res) => {
    const { username, password } = req.body;

    // Hash Password
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: "User registered successfully!" });
    } catch (error) {
        res.status(400).json({ message: "Error registering user", error });
    }
});

// User Login
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ message: "User not found" });

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign({ username: user.username }, "secret_key", { expiresIn: "1h" });
    res.json({ message: "Login successful", token });
});

// CRUD Operations for Quiz
// Get All Questions
app.get("/quiz", authenticateToken, async (req, res) => {
    const quizzes = await Quiz.find();
    res.json(quizzes);
});

// Add a Question
app.post("/quiz", authenticateToken, async (req, res) => {
    const { question, choices, correct } = req.body;

    try {
        const newQuiz = new Quiz({ question, choices, correct });
        await newQuiz.save();
        res.status(201).json({ message: "Question added successfully!" });
    } catch (error) {
        res.status(400).json({ message: "Error adding question", error });
    }
});

// Delete a Question
app.delete("/quiz/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        await Quiz.findByIdAndDelete(id);
        res.status(200).json({ message: "Question deleted successfully!" });
    } catch (error) {
        res.status(400).json({ message: "Error deleting question", error });
    }
});

// Start Server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
