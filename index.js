const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const app=express();
app.use(express.json());
require("dotenv").config();

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432, // Default port for PostgreSQL
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const userCheck = await pool.query(
      "SELECT * FROM users WHERE username=$1",
      [username]
    );
    if (userCheck.rows.length > 0) {
      return res.json("User already exists");
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await pool.query(
      "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *",
      [username, hashedPassword]
    );

    res
      .status(200)
      .json({ message: "User created successfully", user: newUser.rows[0] });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({message: "Server error"});
  }
});

app.post('/login',async (req,res)=>{
    const {username,password}=req.body;
    try{
        const userCheck=await pool.query('SELECT * FROM users WHERE username=$1',[username]);
        if(userCheck.rows.length===0){
            return res.json('Invalid credentials');
        }
        const user=userCheck.rows[0];
        const isPasswordValid=await bcrypt.compare(password,user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const token=jwt.sign({id:user.id},'123');
        res.json({token});
    }
    catch(err){
        console.error(err.message);
        res.status(500).json({message: "Server error"});
    }
})
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];

    const token = authHeader && authHeader.split(' ')[1];
    console.log(token);
    if (!token) return res.status(401).json({ message: 'Access token missing' });

    jwt.verify(token,'123', (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expired token' });

        req.user = user;
        next();
    });
};
app.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: `Hello, ${req.body.username}! This is a protected route.` });
});
app.listen(3000, () => {
  console.log("Server is running on port 3000");
});