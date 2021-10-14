const router = require("express").Router();
const bcrypt = require("bcryptjs");
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const User = require("../users/users-model");
const jwt = require("jsonwebtoken");

router.post("/register", validateRoleName, (req, res, next) => {
  const { username, password, role_name } = req.body;
  const hash = bcrypt.hashSync(password, 8);

  User.add({ username, password: hash, role_name })
    .then((newUser) => {
      res.status(201).json(newUser);
    })
    .catch((err) => {
      next(err);
    });
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  const buildToken = (user) => {
    const payload = {
      subject: user.user_id,
      role_name: user.role_name,
      username: user.username,
    };
    const options = {
      expiresIn: "1d",
    };
    return jwt.sign(payload, JWT_SECRET, options);
  };

  if (bcrypt.compareSync(req.body.password, req.user.password)) {
    const token = buildToken(req.user);
    res.status(200).json({
      message: `${req.user.username} is back!`,
      token,
    });
  } else {
    next({ status: 401, message: "Invalid credentials" });
  }
});

module.exports = router;
