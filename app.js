const express = require('express')
const mongoose = require('mongoose')
const cors = require('cors')
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('./model/user');
require("dotenv").config()

const app = express()
app.use(cors())
app.use(express.json())
app.use(express.urlencoded())

mongoose.connect(process.env.MONGOURI, { useNewUrlParser: true, useUnifiedTopology: true }, (err) => { if (err) console.log(err); app.listen(process.env.PORT) })

app.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        res.status(201).json({ message: 'User registered successfully', redirect: true });
    } catch (error) {
        res.status(500).json({ message: error.message, redirect: false });
    }
});
app.post('/login', async (req, res) => {
    // console.log(req.body)
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            res.status(401).json({ message: 'No email found' });
            return;
        }
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            res.status(401).json({ message: 'Invalid email or password' });
            return;
        }
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ token });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.get("/data", async (req, res) => {
    if (!(Date.now() >= jwt.decode(req.headers.token, process.env.JWT_SECRET).exp * 1000)) {
        const token = req.headers.token;
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET)

        const user = await User.findById(decodedToken.userId);
        if (!user) {
            res.status(401).json({ message: 'Invalid token' });
            return;
        }
        res.status(201).json({ user, redirect: false });
    }
    else {
        console.log(jwt.decode(req.headers.token, process.env.JWT_SECRET), "logged out")
        res.status(403).json({ message: "please login again", redirect: true });
    }
})

app.post("/data", async (req, res) => {
    if (!(Date.now() >= jwt.decode(req.body.token, process.env.JWT_SECRET).exp * 1000)) {
        const token = req.body.token;
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET)

        const { data, previousRate, totalRate } = req.body
        const user = await User.findByIdAndUpdate(decodedToken.userId, { data, previousRate, totalRate })
        if (!user) {
            res.status(401).json({ message: 'Invalid token' });
            return;
        }
        console.log('data updated')
        res.status(201).json({ message: 'data updated' });
    }
    else {
        console.log(jwt.decode(req.headers.token, process.env.JWT_SECRET), "logged out")
        res.status(403).json({ message: "please login again", redirect: true });
    }
})