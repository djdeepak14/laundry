require('dotenv').config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const app = express();

// ---------------------
// Environment Validation
// ---------------------
const { MONGO_URI, JWT_SECRET, PORT = 5001 } = process.env;
if (!MONGO_URI) throw new Error("MONGO_URI is not defined in .env");
if (!JWT_SECRET) throw new Error("JWT_SECRET is not defined in .env");

// ---------------------
// Middleware
// ---------------------
const allowedOrigins = [
  process.env.FRONTEND_URL || 'http://localhost:3000',
  'http://localhost:3001'
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true); // allow Postman or curl
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(bodyParser.json());

// ---------------------
// MongoDB Connection
// ---------------------
mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err.message);
    process.exit(1);
  });

// ---------------------
// Schemas & Models
// ---------------------
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
});

const bookingSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  slotId: { type: String, required: true },
  machine: { type: String, required: true },
  machineType: { type: String, required: true },
  dayName: { type: String, required: true },
  date: { type: Date, required: true },
  timeSlot: { type: String, required: true },
  timestamp: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);
const Booking = mongoose.model("Booking", bookingSchema);

// ---------------------
// JWT Middleware
// ---------------------
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: "No token provided" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

// ---------------------
// Routes
// ---------------------
app.get("/", (req, res) => res.send("🚀 Laundry backend is running!"));

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: "Username and password required" });

    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    await new User({ username, password: hashedPassword }).save();

    res.json({ message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: "Username and password required" });

    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ message: "Invalid username or password" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid username or password" });

    const token = jwt.sign({ id: user._id, username }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token, userId: user._id });
  } catch {
    res.status(500).json({ message: "Internal server error" });
  }
});

// Bookings routes
app.get("/bookings", verifyToken, async (req, res) => {
  const bookings = await Booking.find({ userId: req.user.id });
  res.json(bookings);
});

app.post("/bookings", verifyToken, async (req, res) => {
  const { slotId, machine, machineType, dayName, date, timeSlot, timestamp } = req.body;
  if (!slotId || !machine || !machineType || !dayName || !date || !timeSlot || !timestamp)
    return res.status(400).json({ message: "All booking fields required" });

  const booking = new Booking({ userId: req.user.id, slotId, machine, machineType, dayName, date, timeSlot, timestamp });
  await booking.save();
  res.json(booking);
});

app.delete("/bookings/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid booking ID" });

  const booking = await Booking.findOneAndDelete({ _id: id, userId: req.user.id });
  if (!booking) return res.status(404).json({ message: "Booking not found or not authorized" });

  res.json({ message: `Booking ${id} deleted` });
});

// ---------------------
// Start server
// ---------------------
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
