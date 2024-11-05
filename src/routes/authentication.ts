import bcrypt from 'bcrypt';
import { Application } from 'express';
import { authGuard } from '../guards/auth.guard';
import { users, blacklistedTokenFamilies as blacklist, usedTokens } from '../store';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { v4 as uuid } from 'uuid';

const accessTokenExpiration = process.env.ACCESS_TOKEN_EXPIRATION || 3600;
const refreshTokenExpiration = process.env.REFRESH_TOKEN_EXPIRATION || 604800;
const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET || 'THEDOGISONTHETABLE';
const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET || 'THEDOGISONTHETABLE2';

export function setupRoutes(app: Application) {

  app.post('/register', (req, res) => {
    const { email, password, name, surname } = req.body;

    if (!email || !password || !name || !surname) {
      // Incomplete request
      return res.status(400).json({
        error: 'You must provide email, username and password.'
      });
    }
    const user = users.find(u => u.email === email);

    // Already registered
    if (user) {
      return res.status(400).json({
        error: 'This user already exists.'
      });
    }
    bcrypt.hash(password, 10, (err, hash) => {
      if (err) {
        // Generic error
        return res.redirect('/error');
      }
      const newUser = { id: uuid(), email, displayName: name + ' ' + surname, password: hash };
      
      users.push(newUser);

      // Success
      res.json({
        message: 'Successful registration.'
      });
    });
  });

  app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: 'You need to provide email and password.'
      })
    }

    const user = users.find(u => u.email === email);

    if (!user) {
      return res.status(401).json({
        message: 'User not found.'
      })
    }
    bcrypt.compare(password, user.password, (err, result) => {
      if (err || !result) {
        return res.status(401).json({
          message: 'Incorrect password.'
        })
      }

      // Successful authentication
      const accessToken = jwt.sign({
        email: email,
        displayName: user.displayName,
      }, accessTokenSecret, {
        expiresIn: accessTokenExpiration,
        subject: user.id,
        jwtid: uuid()
      });

      const refreshToken = jwt.sign({
        familyId: uuid()
      }, refreshTokenSecret, {
        expiresIn: refreshTokenExpiration,
        subject: user.id,
        jwtid: uuid()
      });

      // refreshTokenStore.insert({ userId: user._id, token: refreshToken });

      return res.status(200).json({
        message: 'Successful authentication.',
        access_token: accessToken,
        refresh_token: refreshToken
      })
    });
  });

  app.post("/logout", authGuard, (req, res) => {
    const refreshToken = req.body.refresh_token;

    // If a Refresh Token is supplied, blacklist all of its family.
    if (refreshToken) {
      jwt.verify(refreshToken as string, refreshTokenSecret, (err, payload) => {
        if (payload) {
          const currentTimestamp = Math.floor(new Date().getTime() / 1000);

          blacklist.push({
            blacklistedAt: currentTimestamp,
            familyId: (payload as any).familyId
          });
        }
      });
    }
    res.json({
      message: 'Logged out. Throw away your tokens!'
    });
  });

  /**
   * Exhange a Refresh Token for a new token pair.
   * Implements Refresh Token Rotation and Reuse Detection.
   */
  app.post('/token', (req, res) => {
    const { refresh_token: oldRefreshToken } = req.body;

    // Token not provided.
    if (!oldRefreshToken) {
      return res.status(401).json({
        message: 'You must provide a refresh_token.'
      });
    }

    jwt.verify(oldRefreshToken as string, refreshTokenSecret, (err, payload) => {
      // This Refresh Token has expired or it's been tampered with.
      if (err) {
        return res.status(403).json({
          message: 'Invalid refresh_token.'
        });
      }

      const currentTimestamp = Math.floor(new Date().getTime() / 1000);

      const blacklistedFamily = blacklist.find(b => b.familyId === (payload as any).familyId);
      const usedToken = usedTokens.find(u => u.token === oldRefreshToken);

      // Reuse Detection
      if (usedToken) {
        // Blacklist all of this token's family
        blacklist.push({
          blacklistedAt: currentTimestamp,
          familyId: (payload as JwtPayload).familyId
        });

        return res.status(403).json({
          message: 'Reuse detected, you must re-authenticate.'
        });
      }

      // Token was blacklisted
      if (blacklistedFamily) {
        return res.status(403).json({
          message: 'Invalid refresh_token.'
        });
      }

      // Valid refresh token: nothing happened!
      const accessToken = jwt.sign({
        email: (payload as JwtPayload).email,
        displayName: (payload as JwtPayload).displayName,
      }, accessTokenSecret, {
        expiresIn: accessTokenExpiration,
        subject: (payload as JwtPayload).sub,
        jwtid: uuid()
      });

      const refreshToken = jwt.sign({
        familyId: (payload as JwtPayload)?.familyId
      }, refreshTokenSecret, {
        expiresIn: refreshTokenExpiration,
        subject: (payload as JwtPayload)?.sub,
        jwtid: uuid()
      });

      usedTokens.push({
        token: oldRefreshToken,
        familyId: (payload as JwtPayload)?.familyId,
        usedAt: currentTimestamp
      });

      return res.status(200).json({
        message: 'Tokens refreshed. Throw away the previous ones.',
        access_token: accessToken,
        refresh_token: refreshToken
      })
    })
  })

  /**
   * Gets the user's info.
   */
  app.get("/me", authGuard, (req, res) => {

    const user = users.find(u => u.id === req.userId);

    if (!user) {
      return res.status(401).json({
        error: 'User not found.'
      });
    }

    return res.json({
      email: user?.email,
      displayName: user?.displayName,
    });
  });
}
