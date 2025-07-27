const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const mysql = require('mysql');
const connection = require('../db-config')

function init(passport) {
  passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    connection.query('SELECT * FROM admin WHERE email = ?', [email], async (error, results) => {
      if (error) {
        return done(error);
      }

      if (!results || results.length == 0) {
        return done(null, false, { message: 'Email Doesnt exist/ Invalid Email' });
      }

      const admin = results[0];

      bcrypt.compare(password, admin.password, (error, match) => {
        if (error) {
          return done(error);
        }

        if (match) {
          return done(null, admin, { message: 'Logged in successfully' });
        } else {
          return done(null, false, { message: 'Incorrect Email and password' });
        }
      });
    });
  }));

  passport.serializeUser((admin, done) => {
    done(null, admin.id);
  })

  passport.deserializeUser((id, done) => {
    connection.query('SELECT * FROM admin WHERE id = ?', [id], (error, results) => {
      if (error) {
        return done(error);
      }

      return done(null, results[0]);
    });
  });
}

module.exports = init;