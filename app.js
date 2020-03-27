//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
  bodyParser.urlencoded({
    extended: true
  })
);

app.use(
  session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String, //this is the ID that google return
  secret: String
});

userSchema.plugin(passportLocalMongoose); //to hash and salt password and save to to the mongo database and some method for simple code
userSchema.plugin(findOrCreate); // this is a module

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy()); //tell passport to use local strategy

//the origin serialize code from passport should be used for all strategies
passport.serializeUser(function(user, done) {
  //to turn the userid to session
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  //to destroy the session
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets", //where u want to go after auth
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" //a fix to draw profile without google+
    },
    function(accessToken, refreshToken, profile, cb) {
      console.log(profile);

      User.findOrCreate({ googleId: profile.id }, function(err, user) {
        //find or create the return google id in our db
        return cb(err, user);
      });
    }
  )
);

app.get("/", function(req, res) {
  res.render("home");
});

//the route when you click the google button
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

//the route after google auth, which is the redirect from google.
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  }
);

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

//show all secrets on the screen
app.get("/secrets", function(req, res) {
  User.find({ secret: { $ne: null } }, function(err, foundUsers) {
    //$ne: not equals
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        //found user is an object with all user data
        res.render("secrets", { usersWithSecrets: foundUsers });
      }
    }
  });
});

//the submit secret page
app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) {
    //req.isAuthenticated() will return true if user is logged in
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

//post a secret by auth user
app.post("/submit", function(req, res) {
  const submittedSecret = req.body.secret;

  //Once the user is authenticated and their session gets saved, their user details are saved to req.user.
  // console.log(req.user.id);

  User.findById(req.user.id, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function() {
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});

//register a new user
app.post("/register", function(req, res) {
  User.register({ username: req.body.username }, req.body.password, function(
    //thanks to passport local mongoose, we don`t need to touch mongoose
    err,
    user
  ) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", function(req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  // used to establish a login session
  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.listen(3000, function() {
  console.log("Server started on port 3000.");
});
