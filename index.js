const express = require('express');
const admin = require('firebase-admin');
const bodyParser = require('body-parser');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

const port = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET;

const allowedOrigins = ['https://plm-sap.vercel.app', 'http://127.0.0.1:5173'];

const allowCors = (req, res, next) => {
  const origin = req.headers.origin;

  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET,OPTIONS,PATCH,DELETE,POST,PUT'
  );
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Origin, X-Api-Key, Authorization'
  );

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  next();
};

app.use(allowCors);

admin.initializeApp({
  credential: admin.credential.cert({
    type: process.env.FIREBASE_TYPE,
    project_id: process.env.PROJECT_ID,
    private_key_id: process.env.PRIVATE_KEY_ID,
    private_key: process.env.PRIVATE_KEY,
    client_email: process.env.CLIENT_EMAIL,
    client_id: process.env.CLIENT_ID,
    auth_uri: process.env.AUTH_URI,
    token_uri: process.env.TOKEN_URI,
    auth_provider_x509_cert_url: process.env.AUTH_PROVIDER_X509_CERT_URL,
    client_x509_cert_url: process.env.CLIENT_X509_CERT_URL
  })
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  console.log('Auth header:', authHeader);

  const token = authHeader && authHeader.split(' ')[1];
  console.log('Token:', token);

  if (token == null) {
    console.log('No token, authorization denied');
    return res.status(401).json({ message: 'No token, authorization denied' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('Token error:', err);
      return res
        .status(403)
        .json({ message: 'Token error', error: err.message });
    }

    req.user = user;
    next();
  });
}

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});

app.post('/login', async (req, res) => {
  const { plmEmailAddress, password } = req.body;

  try {
    const usersCollection = admin.firestore().collection('users');
    const emailQuery = usersCollection.where(
      'PLM Email Address',
      '==',
      plmEmailAddress
    );

    const querySnapshot = await emailQuery.get();

    if (querySnapshot.empty) {
      console.log('No matching documents.');
      return res.status(401).json({ message: 'No matching documents.' });
    }

    querySnapshot.forEach((doc) => {
      console.log(doc.id, '=>', doc.data());
      const user = doc.data();

      // Use studentNo as password if password is not set
      const validPassword = user.password || user.id;

      // Verify provided password
      if (password !== validPassword) {
        return res.status(401).json({ message: 'Incorrect password.' });
      }

      const accessToken = jwt.sign(user, JWT_SECRET, { expiresIn: '1h' });

      console.log('Origin:', req.headers.origin);

      res.status(200).json({ token: accessToken, user });
      return;
    });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ message: 'An error occurred while logging in.' });
  }
});

app.get('/protected', authenticateToken, (req, res) => {
  res.status(200).json({ message: 'Access granted to protected route' });
});
