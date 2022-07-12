require('dotenv/config');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { verify } = require('jsonwebtoken');
const {hash, compare} = require('bcryptjs');
const { fakeDB } = require('./fakeDB');
const { createAccessToken, createRefreshToken, sendAccessToken, sendRefreshToken } = require('./tokens');


//Creating the express server
const server = express();


//Use express middleware for easier cookie handling
server.use(cookieParser());
server.use(cors({origin:'http://localhost:3000', credentials: true}));
//Needed to be able to read body data
server.use(express.json()); //To support JSON-encoded bodies
server.use(express.urlencoded({extended:true})); //Supports url-encoded bodies


//Endpoints...

//User register
server.post("/register", async (req, res) => {
    const {email, password} = req.body;
    try{
        //1. Check if the user exist
        const user = fakeDB.find(user => user.email === email);
        if(user) throw new Error('User already exists');
        //2. If user don't exists will hash and save the password.
        const hashedPassword = await hash(password, 10);
        //3. Insert the user in the "database"
        fakeDB.push({
            id:fakeDB.length,
            email,
            password:hashedPassword
        })
        res.send({message:'User created'})
        console.log(fakeDB);
    }
    catch(err){
        res.send({
            error:`${err.message}`
        });
    }
});



//User login
server.post("/login", async (req, res) => {
    const{email,password} = req.body;
    try{
        console.log(fakeDB);
        //1. Find user in our "Database";
        const user = fakeDB.find(user => user.email === email);
        if(!user) throw new Error('User not found!');
        //2. Compare encrypted password and see if it checks out. Send error if not.
        const valid = await compare(password, user.password);
        if(!valid) throw new Error('Password not correct!');
        //3. Create refresh - and Accesstoken
        const accesstoken = createAccessToken(user.id);
        const refreshToken = createRefreshToken(user.id);
        //4. Put the refresh token in the "database";
        user.refreshToken = refreshToken;
        console.log(fakeDB);
        //5. Send the refresh token as a cookie and access token as a regular response
        sendRefreshToken(res, refreshToken);
        sendAccessToken(req, res, accesstoken);
    }
    catch(err){
        res.send({
            error:`${err.message}`
        })
    }
});


//User log out
server.post("/logout", (_req, res) => {
    res.clearCookie('refreshtoken');
    return res.send({
        message:"Logged out"
    })
});






//Putting our server on
server.listen(process.env.PORT, () =>
    console.log(`Server running at port ${process.env.PORT}`)
);  