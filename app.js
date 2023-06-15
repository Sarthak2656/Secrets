const express=require("express");
require('dotenv').config();
const bodyParser=require("body-parser");
const ejs=require("ejs");
const app=express();
const findOrCreate=require("mongoose-findorcreate")
app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({
    extended:true
}));

const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy=require('passport-github2').Strategy;
const TwitterStrategy=require('passport-twitter').Strategy;

var session = require('express-session')
var passport=require("passport");
const passportLocalMongoose=require("passport-local-mongoose");
var mongoose = require('mongoose');

app.use(session({
  secret: process.env.PASSPORT_SEC,
  resave: false,
  saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

var mongoDB = "mongodb+srv://"+process.env.MONGO+"@cluster0.spej2gf.mongodb.net/userDB";
mongoose.connect(mongoDB, { useNewUrlParser: true });

const userSchema=new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    twitterId:String,
    githubId:String,
    secret:String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User=new mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://secret-qxqn.onrender.com/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: "https://secret-qxqn.onrender.com/auth/github/secrets"
},
function(accessToken, refreshToken, profile, done) {
  User.findOrCreate({ githubId: profile.id }, function (err, user) {
    return done(err, user);
  });
}
));

passport.use(new TwitterStrategy({
  consumerKey: process.env.TWITTER_CONSUMER_KEY,
  consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
  callbackURL: "https://secret-qxqn.onrender.com/auth/twitter/secrets"
},
function(token, tokenSecret, profile, cb) {
  User.findOrCreate({ twitterId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));
app.get("/",function(req,res)
{
    res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ["profile"] }));

  app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

  app.get('/auth/github',
  passport.authenticate('github', { scope: [ 'user:email' ] }));

app.get('/auth/github/secrets', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

  app.get('/auth/twitter',
  passport.authenticate('twitter'));

app.get('/auth/twitter/secrets', 
  passport.authenticate('twitter', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get("/login",function(req,res)
{
    res.render("login");
});

app.get("/register",function(req,res)
{
    res.render("register");
});

app.get("/secrets",function(req,res)
{
    User.find({"secret":{$ne:null}}).then(function(foundUser)
    {
      res.render("secrets",{userswithsecrets:foundUser});
    });
});

app.get("/submit",function(req,res)
{
  if(req.isAuthenticated())
  res.render("submit");
  else
  res.redirect("/login");
});

app.post("/submit",function(req,res)
{
  const userSecret=req.body.secret;
  User.findById(req.user.id).then(function(foundUser)
  {
    foundUser.secret=userSecret;
    foundUser.save();
    res.redirect("/secrets");
  });
});

app.get("/logout",function(req,res)
{
    req.logout(function(err)
    {
        res.redirect("/");
    });
});

app.post("/register",function(req,res)
{
    User.register({username:req.body.username},req.body.password,function(err,user)
    {
        if(err)
        {
            console.log(err);
            res.redirect("/");
        }
        else
        passport.authenticate("local")(req,res,function(){
            res.redirect("/secrets");
        });
    });
});

app.post("/login",function(req,res)
{
    const user=new User({
        username:req.body.username,
        password:req.body.password
    });
    req.login(user,function(err)
    {
        if(err)
        console.group(err);
        else
        {
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
});


app.listen(3000,function(){
    console.log("Server started on port 3000");
});