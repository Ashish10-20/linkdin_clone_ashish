const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const User = require("./models/User");
const Post = require("./models/Post");

const app = express();
app.use(express.json());
app.use(cors());

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Mongo Connected"))
  .catch((err) => console.log(err));

app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  await User.create({ name, email, password: hashed });
  res.json({ message: "User registered" });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.json({ error: "User not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.json({ error: "Incorrect password" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.json({ token, user });
});

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  try {
    const data = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = data.id;
    next();
  } catch {
    res.json({ error: "Invalid token" });
  }
}

app.post("/post", auth, async (req, res) => {
  const post = await Post.create({ user: req.userId, text: req.body.text });
  res.json(post);
});

app.get("/posts", async (req, res) => {
  const posts = await Post.find().populate("user").sort({ createdAt: -1 });
  res.json(posts);
});

app.listen(process.env.PORT, () =>
  console.log("Server running on", process.env.PORT)
);
