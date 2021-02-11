const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const User = require('../models/User.model');

router.get('/signup', (req, res) => {
  res.render('signup');
});

router.get('/login', (req, res) => {
  res.render('login');
});

router.post('/signup', (req, res) => {
  const { username, password } = req.body;

  if (username === '' || password === '') {
    res.render('signup', {
      errorMessage: 'Indicate username and password'
    }
    );
    return;
  }

  const passwordRegex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  if (passwordRegex.test(password) === false) {
    res.render('signup',
      { errorMessage: 'Weak password' });
    return;
  }

  User.findOne({ username: username })
    .then((user) => {
      if (user) {
        res.render('signup',
          { errorMessage: 'User already exists' }
        );
        return;
      }

      const saltRounds = 10;
      const salt = bcrypt.genSaltSync(saltRounds);
      const hashPassword = bcrypt.hashSync(password, salt);

      User.create({ username, password: hashPassword })
        .then(() => {
          res.redirect('/');
        })
        .catch((error) => {
          if (error.code === 11000) {
            render('signup', { errorMessage: 'username should be unique' });
          }
        });


    });

});


router.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    res.render('login', {
      errorMessage: 'Please enter both username and password'
    });
    return;
  }

  User.findOne({ username: username })
    .then((user) => {
      if (!user) {
        res.render('login', {
          errorMessage: 'Invalid Login'
        });
        return;
      }

      if (bcrypt.compareSync(password, user.password)) {

        req.session.currentUser = user;
        res.redirect('/');
        //res.render('index', { user: user });
      } else {
        res.render('login', {
          errorMessage: 'Invalid Login'
        })
      }
    });


});

router.post('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});


module.exports = router;