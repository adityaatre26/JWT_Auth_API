import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import user from "./models/user.js";
import jwt from "jsonwebtoken";
import { configDotenv } from "dotenv";
import logger from "./logger.js";

configDotenv();

const app = express();

//to parse json data
app.use(express.json());

//connect to mongo database
main().catch((err) => console.log(err));

async function main() {
  await mongoose.connect(process.env.MONGODB_URI);
  console.log("Connection Initiated");
}

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const isUserExisting = await user.findOne({ username });
    if (isUserExisting) {
      return res.status(400).json({ message: "User already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10); //2nd argument decides the number of cycles
    const User = new user({
      username,
      password: hashedPassword,
    });
    await User.save();

    const token = jwt.sign(
      { id: User._id, username: User.username },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h", //time upto which the token is valid
      }
    );
    res.status(200).json({ message: "User registered successfully", token });
  } catch (err) {
    logger.error("Error occurred on the server side", err);
    res.status(500).json({ message: "Error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const User = await user.findOne({ username });
    if (!User) {
      logger.error(err);
      return res.status(400).json({ message: "Invalid username or password" });
    }
    const isValidPassword = await bcrypt.compare(password, User.password);
    if (!isValidPassword) {
      logger.error(err);
      return res.status(400).json({ message: "Invalid username or password" });
    }
    //creates a token with parameters provided by the user
    const token = jwt.sign(
      { id: User._id, username: User.username },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );
    res.status(200).json({ message: "User logged in successfully", token });
  } catch (err) {
    logger.error("Error occurred on the server side", err);
    res.status(500).json({ message: "Error" });
  }
});

const jwtMiddleware = async (req, res, next) => {
  //splits the header with space as parameter, maps it to an array and then takes the string at 1st index
  const token = req.headers.authorization.split(" ")[1];
  if (!token) {
    logger.error("Token Problem", err);
    return res.status(401).json({ message: "Unauthorized" });
  }
  try {
    const userDecoded = jwt.verify(token, process.env.JWT_SECRET);
    req.User = userDecoded;
    next();
  } catch (err) {
    logger.error("Error occurred", err);
    return res.status(401).json({ message: "Invalid Token" });
  }
};

app.put("/edit", jwtMiddleware, async (req, res) => {
  try {
    const userId = req.User.id;
    const { username, password } = req.body;
    if (!userId) {
      logger.error("Auth error", err);
      return res.status(400).json({ message: "Please Login/Signup" });
    }
    const updatedFields = {};
    if (username) {
      updatedFields.username = username;
    }
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updatedFields.password = hashedPassword;
    }
    const updatedUser = await user.findByIdAndUpdate(userId, updatedFields, {
      new: true,
      runValidators: true,
    });
    res.status(200).json(updatedUser);
  } catch (err) {
    logger.error("Error occurred on the server side", err);
    res.status(500).json({ message: "Error" });
  }
});

app.delete("/delete", jwtMiddleware, async (req, res) => {
  try {
    const userId = req.User.id;
    const deletedUser = await user.findByIdAndDelete(userId);
    res.status(200).json(deletedUser);
  } catch (err) {
    logger.error("Error occurred on the server side", err);

    res.status(500).json({ message: "Error" });
  }
});

app.get("/sortedUsers", async (req, res) => {
  try {
    let { sortBy = "username", order = "ascending" } = req.query;
    if (order == "descending") {
      order = -1;
    } else {
      order = 1;
    }
    let sortedUsers = await user.find().sort({ [sortBy]: order });
    res.status(200).json(sortedUsers);
  } catch (err) {
    logger.error("Couldn't find users", err);
    res.status(500).json({ message: "Error" });
  }
});

app.listen("5000", () => {
  console.log("server is running on port 5000");
});
