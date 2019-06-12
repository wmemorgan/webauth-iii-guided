const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')

const secrets = require('../config/secrets')
const Users = require('../users/users-model.js');

module.exports = (role) => {
  return (req, res, next) => {
    const token = req.headers.authorization;

    if (token) {
    jwt.verify(token, secrets.jwt, (err, payload) => {
      if (err) {
        res.status(403).json({ message: `You are not authorized` })
      } else {
        if (role !== payload.userRole) {
          res.status(403).json({ message: `You don't have permission for this resource`})
        } else {
          req.userId = payload.userId
          next()
        }
      }
    })

    } else {
      res.status(400).json({ message: 'No credentials provided' });
    }
  }
}
