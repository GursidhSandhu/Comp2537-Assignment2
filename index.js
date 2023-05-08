require('dotenv').config();
require('./utils.js');

// express module
const express = require('express');

// express-session module
const session = require('express-session');

// connected to mongoDB
const MongoStore = require('connect-mongo');

// bcrypt module
const bcrypt = require('bcrypt');

const saltRounds = 12;

// run on PORT variable or 3000
const port = process.env.PORT || 3000;

// variable to use express module
const app = express();

// variable to use joi module
const Joi = require('joi');

// allows us to use parsed data from form to request body
app.use(express.urlencoded({extended:false}));

// telling express we want to use render EJS files
app.set('view engine', 'ejs');

// links for the header navbar
const navLinks = [
    {name: 'Home', link: '/'},
    {name: 'Login', link: '/login'},
    {name: 'Members', link: '/members'},
    {name: 'Admin', link: '/admin'},
    {name: '404', link: '/*'}
]

// how long the session is valid for : 1 hour
const expireTime = 1* 60 * 60 * 1000;

// secret variables located in .env file
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

// import the database object from databaseConnection.js file
var {database} = include('databaseConnection');

// reference to users collection in database
const userCollection = database.db(mongodb_database).collection('users');

// linking to mongoDb database
var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/test`,
    crypto: {
        secret: mongodb_session_secret
    }
})

// using sessions
app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}
));

// method that checks if a session is valid
function isValidSession(req) {
    if(req.session.authenticated){
        return true;
    } else {
        return false;
    }
}

// middleware function
function sessionValidation(req,res,next){
    if(isValidSession(req)){
        next();
    } else {
        res.redirect('/');
    }
}

// method that checks if an user type is admin
function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

// middleware function
function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized", navLinks: navLinks});
        return;
    }
    else {
        next();
    }
}

// creating a home page for users to either click login or signup
app.get('/', (req,res) => {

     // if the session is already valid
    if (req.session.authenticated) {
         // local variable to hold username of current session
        var username = req.session.username;
        res.render('loggedIn', {username: username, navLinks: navLinks});
        return;
    }
    res.render('home', {navLinks: navLinks});
});

// method to check nosql injection attacks
app.get('/nosql-injection', async (req,res) => {
	var email = req.query.email;

	if (!email) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}

    // validate that the email is correct
	const schema = Joi.string().email().required();
	const validationResult = schema.validate(email);

    // if the validation results in an error then assume an attack was detected
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

    // search for the email in users collection from database
	const result = await userCollection.find({email: email}).project({username: 1, password: 1, _id: 1}).toArray();

   res.send(`<h1>Hello ${req.session.username}</h1>`);
});

// creating a page for users to login
app.get('/login', (req,res) => {
    res.render('login', {navLinks: navLinks});
});

// check if the attempt to login is valid or not
app.post('/loginSubmit', async(req,res) => {
    // local variables to hold current email and password
    var email = req.body.email;
    var password = req.body.password;

    // verify that the email entered is a valid email
    const schema = Joi.string().email().required();
	const validationResult = schema.validate(email);
    
    // if the email is not valid then redirect user to login again
	if (validationResult.error != null) {
        res.render('loginAttempt1', {navLinks: navLinks});
	   return;
    }

    // find the user in the database and store in result variable
    const result = await userCollection.find({email: email}).project({username: 1, password: 1, user_type: 1, _id: 1}).toArray();

    // redirect user to login if the email is not found in database 
    // if the email pops up more than once then user will be prompted to login again
	if (result.length != 1) {
        res.render('loginAttempt2', {navLinks: navLinks});
		return;
	}
    // if email found then compare the given password to stored password
    // if passwords match then redirect user to members page and start valid session
	if (await bcrypt.compare(password, result[0].password)) {

		req.session.authenticated = true;
		req.session.email = email;
        req.session.username = result[0].username;
        req.session.user_type = result[0].user_type;
		req.session.cookie.maxAge = expireTime;
        
		res.render('members', {username: req.session.username, navLinks: navLinks});
		return;
    }
    // if email exists but passwords dont match then prompt user to login again.
	else {
        var html = 
        res.render('loginAttempt3', {navLinks: navLinks});
		return;
	}
});

// creating a page for users to signup
app.get('/signup', (req,res) => {
    res.render('signup', {navLinks: navLinks});
});

// action that happens when new user is create
app.post('/signupSubmit', async(req,res) => {
    // parse whats taken in from form field
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    //validate that the following fields are completed correctly
	const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
			password: Joi.string().max(20).required()
		});

	 const validationResult = schema.validate({username, email, password});

    // if validation throws an error then redirect user to signup page
	 if (validationResult.error != null) {
	   var error = validationResult.error;
       res.render('signupAttempt1', {error: error, navLinks: navLinks});
	   return;
   } 
       // check if email already exists in the user collection
       var existingUser = await userCollection.findOne({ email: email });

   if (existingUser) {
    res.render('signupAttempt2', {navLinks: navLinks});
       return;
    } 

   // hash the inserted password
   var hashedPassword = await bcrypt.hash(password, saltRounds);

if(username == 'gursidh' ){
        // gursidh is the only user that has admin access
        await userCollection.insertOne({username: username, email: email, password: hashedPassword, user_type: "admin"});
        req.session.user_type = 'admin';
} else {
        // every other user is just a normal user
	await userCollection.insertOne({username: username, email: email, password: hashedPassword, user_type: "user"});
    req.session.user_type = 'user';
}

    // if passes validation code, begin session and redirect to members page
    req.session.authenticated = true;
    req.session.cookie.maxAge = expireTime;
    req.session.username = username;
    res.render('members', {username: req.session.username, navLinks: navLinks});
   
});

app.get('/changeToUser/:name', async(req,res) => {
    await userCollection.updateOne({username: req.params.name}, {$set: {user_type: 'user'}});
   // const result = await userCollection.find().project({username: 1, user_type: 1, _id: 1}).toArray();
    res.redirect('/admin');
});

// method that changes user type to admin
app.get('/changeToAdmin/:name', async(req,res) => {
    await userCollection.updateOne( { username: req.params.name },{ $set: { user_type: 'admin' } });
   // const result = await userCollection.find().project({username: 1, user_type: 1, _id: 1}).toArray();
    res.redirect('/admin');
});

// members area page
app.use('/members', sessionValidation);
app.get('/members', (req,res) => {
        res.render('members', {username: req.session.username,navLinks: navLinks});
});

// making an admins page
app.get('/admin', sessionValidation, adminAuthorization, async(req,res) => {
    // store every user in an array
    const result = await userCollection.find().project({username: 1, user_type: 1, _id: 1}).toArray();
    res.render('admin', {users: result, navLinks: navLinks});
});

// page that represents a user is logged out
app.get('/logout', (req, res) => {
    // destroy current session
    req.session.destroy();
    // redirect to home page
    res.redirect('/');
});

// using the direct path of public folder
app.use(express.static(__dirname + "/public"));

// catch any page that does not exist and make it a 404 page
app.get("*", (req,res) => {
    res.status(404);
    res.render('404', {navLinks: navLinks});
});
    
app.listen(port, () => {
    console.log("Node application listening on port " + port);
});
