//jshint esversion:6
require('dotenv').config();
const express = require("express")
const bodyparser = require("body-parser")
const ejs = require("ejs")
const mongoose = require("mongoose")
const session = require('express-session')
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')

//-----------LEVEL-3 HASHING USING MD5--------------
// const md5 = require("md5");


const app = express();

// console.log(process.env.API_KEY);

app.use(express.static("public"));
app.use(bodyparser.urlencoded({ extended: true }));
app.set("view engine", "ejs");

app.use(session({
    secret: "Our little secret",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/User1DB");

const userschema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

//---------LEVEL-2 AUTHENTICATION ENCRYPTION--------------//
// const encrypt = require("mongoose-encryption")
// const secret = process.env.SECRET;
// userschema.plugin(encrypt,{secret:secret , encryptedFields:["password"] }); 

userschema.plugin(passportLocalMongoose);
userschema.plugin(findOrCreate);

const User = new mongoose.model("user", userschema);

passport.use(User.createStrategy());


passport.serializeUser(function (user, done) {
    done(null, user.id)
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

//------------------------LEVEL-6 AUTH.GO20 -----------------//

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));


app.get("/", function (req, res) {
    res.render("home");
});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });

app.get("/login", function (req, res) {
    res.render("login");
});
app.get("/register", function (req, res) {
    res.render("register");
});
app.get("/secrets", function (req, res) {
    User.find({ "secret": { $ne: null } }, function (err, foundUsers) {
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render("secrets", { UserSecrets: foundUsers });
            }
        }

    });
});

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }

});

app.post("/submit", function (req, res) {
    const submittedScret = req.body.secret;

    User.findById(req.user.id, function (err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret = submittedScret;
                foundUser.save(function () {
                    res.redirect("/secrets")
                });
            }
        }
    });
});

app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (!err) {
            res.redirect("/");
        } else {
            console.log(err);
        }
    });

});

app.post("/register", function (req, res) {

    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register")
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            })
        }
    })

});

app.post("/login", function (req, res) {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            })
        }
    })

});

//------------------LEVEL-4----------------------//

// const bcrypt = require("bcrypt");
// const saltRounds = 10;
// app.post("/register",function(req,res){

//     bcrypt.hash(req.body.password, saltRounds, function(err, hash) {

//     if(req.body.password === req.body.confirmpassword){
//         const Newuser = new User({
//             email:req.body.useremail,
//             password: hash
//         });
//         Newuser.save(function(err){
//             if(!err){
//                 res.render("secrets");
//                 console.log("New User Add");
//             }else{
//                 console.log(err);
//             }
//         });
//     }else{
//         res.send(" Confirm password don't Match");
//     }
//     });

// });

// app.post("/login",function(req,res){

//     const useremail = req.body.username;
//     const password = req.body.password;

//     // const password = md5(req.body.password);

//     User.findOne({email:useremail},function(err,founduser){
//         if(!err){
//             if(founduser){
//                 bcrypt.compare(password, founduser.password, function(err, result) {

//                     if(result === true){
//                         res.render("secrets");
//                     }
//                 });
//             }

//         }else{
//             console.log(err); 
//         }
//     })
// })




app.listen(3000, function () {
    console.log("server started on port 3000");
});