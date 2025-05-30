const express = require("express")
const app = express()
const port = 4000
const cors = require("cors")

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET

const admin = require("firebase-admin");
const serviceAccount = require("./path/to/your/firebase-service-account-key.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const usersRef = db.collection('users');
    const snapshot = await usersRef.where('email', '==', email).get();

    if (snapshot.empty) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const userDoc = snapshot.docs[0];
    const userData = userDoc.data();

    const isPasswordValid = bcrypt.compareSync(password, userData.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: userDoc.id, email: userData.email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/users', async (req, res) => {
  const { email, password } = req.body;

  // Validate input
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  // Check if user already exists
  const existingUser = users.find(user => user.email === email);
  if (existingUser) {
    return res.status(409).json({ error: 'User already exists' });
  }

  // Hash the password
  const passwordHash = await bcrypt.hash(password, 10);

  // Create user
  const newUser = {
    id: users.length + 1,
    email,
    passwordHash
  };

  users.push(newUser);

  res.status(201).json({ message: 'User created successfully', userId: newUser.id });
});

router.post('/verify', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ valid: false });

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ valid: true, decoded });
  } catch (err) {
    res.status(401).json({ valid: false });
  }
});

app.use(express.urlencoded({extended: true}))
app.use(express.json())
app.use(cors({
  origin: ['chrome-extension://felkciicihckbhhllaoleekclambgkjl'],
  credentials: true
}));
app.use(router)

app.listen(port, () => {
    console.log("Listening at " + port)
})