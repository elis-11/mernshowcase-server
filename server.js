import dotenv from "dotenv";
import express from "express";
import session from "express-session";
import cookieParser from "cookie-parser";
import cors from "cors";
import mongoose from "mongoose";
import UserModel from "./models/User.js";
import bcrypt from "bcrypt";

dotenv.config();
mongoose.connect(process.env.MONGOURI);

const app = express();

app.use(express.json());

const saltRounds = Number(process.env.SALT_ROUNDS);

const mongoConnectString = process.env.MONGOURI;
mongoose
  .connect(mongoConnectString, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log(`MongoDB Connected!!!`))
  .catch((err) => console.log(`Error: ${err.message}`));

app.set("trust proxy", 1);
app.use(
  cors({
    origin:
      // process.env.FRONTEND_ORIGIN || "http://localhost:3000",
      process.env.NODE_ENV !== "production"
        ? process.env.FRONTEND_ORIGIN
        : [process.env.FRONTEND_ORIGIN_HTTP, process.env.FRONTEND_ORIGIN_HTTPS],
    credentials: true,
  })
);

app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    proxy: true,
    saveUninitialized: false,
    resave: false,
    cookie: {
      httpOnly: true,
      maxAge: 60 * 60 * 1000 * 24,
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      secure: process.env.NODE_ENV === "production",
    },
  })
);

app.use(cookieParser());

app.get("/", (req, res) => {
  res.send(`
  <h2>Welcome!</h2>
<div>Our routes:</div>
<div>Users: <a href="/users">/users</a></div>
<div> Frontend URL: <a href="${process.env.FRONTEND_ORIGIN}"> ${process.env.FRONTEND_ORIGIN}</a></div>

  `);
});

const userIsInGroup = (user, accessGroup) => {
  const accessGroupArray = user.accessGroups.split(",").map((m) => m.trim());
  return accessGroupArray.includes(accessGroup);
};

app.get("/users", async (req, res) => {
  const user = await UserModel.find({})
    .select("username firstName lastName email accessGroups createdAt")
    .sort({ _id: -1 });
  // const users = await UserModel.find()
  res.json(user);
});

app.post("/login", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  let dbuser = await UserModel.findOne({ username });
  if (!dbuser) {
    dbuser = await UserModel.findOne({ username: "Guest" });
  } else {
    bcrypt.compare(password, dbuser.hash).then((passwordIsOk) => {
      if (passwordIsOk) {
        req.session.user = dbuser;
        req.session.save();
        res.json(dbuser);
      } else {
        res.sendStatus(403);
      }
    });
  }
});

app.get("/currentuser", async (req, res) => {
  let user = req.session.user;
  if (!user) {
    user = await UserModel.findOne({ username: "Guest" });
  }
  res.json(user);
});

app.post("/signup", async (req, res) => {
  const frontendUser = req.body.user;
  if (
    frontendUser.username.trim() === "" ||
    frontendUser.email.trim() === "" ||
    frontendUser.password1.trim() === "" ||
    frontendUser.password1 !== frontendUser.password2
  ) {
    res.sendStatus(403);
  } else {
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(frontendUser.password1, salt);
    const email = frontendUser.email;
    const backendUser = {
      firstName: frontendUser.firstName,
      lastName: frontendUser.lastName,
      username: frontendUser.username,
      email: frontendUser.email,
      // email,
      hash,
      accessGroups: "loggedInUsers, notYetApprovedUsers",
    };
    const dbuser = await UserModel.create(backendUser);
    res.json({
      userAdded: dbuser,
    });
  }
});

app.post("/approveuser", async (req, res) => {
  const id = req.body.id;
  let user = req.session.user;
  if (!user) {
    res.sendStatus(403);
  } else {
    if (!userIsInGroup(user, "admin")) {
      res.sendStatus(403);
    } else {
      const updateResult = await UserModel.findOneAndUpdate(
        { _id: new mongoose.Types.ObjectId(id) },
        { $set: { accessGroups: "loggedInUsers, member" } },
        { new: true }
      );
      res.json({ result: updateResult });
    }
  }
});

app.get("/notyetapprovedusers", async (req, res) => {
  const users = await UserModel.find({
    accessGroups: { $regex: "notYetApprovedUsers", $options: "i" },
  });
  res.json({ users });
});

app.delete("/deleteuser", async (req, res) => {
  const id = req.body.id;
  const user = await UserModel.findByIdAndDelete({
    _id: new mongoose.Types.ObjectId(id),
  });
  res.json({ user });
});

app.get("/logout", async (req, res) => {
  req.session.destroy();
  const user = await UserModel.findOne({ username: "Guest" });
  res.json(user);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, (req, res) => {
  console.log(`Server listening at http://localhost:` + PORT);
});
