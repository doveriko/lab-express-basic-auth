const express = require('express');
const router  = express.Router();

const User = require("../models/users");

// BCrypt to encrypt passwords
const bcrypt = require("bcrypt");
const bcryptSalt = 10;

// Password strength measurement
var zxcvbn = require("zxcvbn");

router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});

router.post("/signup", (req, res, next) => {
  // 1. Deconstruct the `username` and `password` from req.body
  const { username, password } = req.body;

  // 2. Check if `username` or `password` are empty and display error message
  if (username === "" || password === "") {
    res.render("auth/signup", {
      errorMessage: "Indicate a username and a password to sign up",
    });
    return;
  }

  // 3. Check if the username already exists in the collection
  User.findOne({ username: username })
    .then((user) => {
      if (user !== null) {
        res.render("auth/signup", {
          errorMessage: "The username already exists!",
        });
        return;
      }

      // 4. Check the password strength with zxcvbn package
      // if (zxcvbn(password).score < 6) {
      //   res.render("auth/signup", {
      //     errorMessage: "Password too weak, try again",
      //   });
      //   return;
      // }

      // 5. If `username` doesn't exist generate salts and hash the password
      const salt = bcrypt.genSaltSync(bcryptSalt);
      const hashPass = bcrypt.hashSync(password, salt);

      // 6. After hashing the password, create new user in DB
      User.create({
        username,
        password: hashPass,
      })
        .then(() => {
          res.redirect("/");
        })
        .catch((error) => {
          console.log(error);
        });
    })
    .catch((error) => {
      next(error);
    });
});

router.get("/login", (req, res, next) => {
  res.render("auth/login");
});

router.post("/login", (req, res, next) => {
  const theUsername = req.body.username;
  const thePassword = req.body.password;

  if (theUsername === "" || thePassword === "") {
    res.render("auth/login", {
      errorMessage: "Please enter both, username and password to sign up.",
    });
    return;
  }

  User.findOne({ username: theUsername })
    .then((user) => {
      if (!user) {
        res.render("auth/login", {
          errorMessage: "The username doesn't exist.",
        });
        return;
      }
      if (bcrypt.compareSync(thePassword, user.password)) {
        // Create the user session:
        req.session.currentUser = user;
        res.redirect("/");
      } else {
        res.render("auth/login", {
          errorMessage: "Incorrect password",
        });
      }
    })
    .catch((error) => {
      next(error);
    });
});

router.get("/logout", (req, res, next) => {
  req.session.destroy((err) => {
    // cannot access session here
    res.redirect("/login");
  });
});

module.exports = router;
