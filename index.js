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
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}.rye5pig.mongodb.net/test`,
    crypto: {
        secret: mongodb_session_secret
    }
})

// using sessions
app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUnitialized: false,
    resave: true
}
));

var users = [];

// creating a home page for users to either click login or signup
app.get('/', (req,res) => {

     // if the session is already valid
    if (req.session.authenticated) {
         // local variable to hold username of current session
        var username = req.session.username;

        var html = `
        <h2> Hello ${username}! </h2>
        <a href='/members'><button> Go to Members Area </button></a><br>
        <a href='/logout'><button> Logout </button></a>`
        res.send(html);
    }

    var html = `
    <h1> Welcome to Gursidh's Website!</h1>
    <a href='/login'><button>Login</button></a><br>
    <a href='/signup'><button>Signup</button></a>`;
    res.send(html);
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
    var html = `
    <h2> log in </h2>
    <form action = '/loginSubmit' method = 'post'>
    <input name = 'email' type = 'email' placeholder = 'email'><br>
    <input name = 'password' type = 'password' placeholder = 'password'><br>
    <button>Submit</button>
    </form>`;
    res.send(html);
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
        var html = `
        <h2> Invalid email.</h2>
        <a href='/login'><h2> try again </h2></a>`;
        res.send(html);
	   return;
    }

    // find the user in the database and store in result variable
    const result = await userCollection.find({email: email}).project({username: 1, password: 1, _id: 1}).toArray();

    console.log(result);

    // redirect user to login if the email is not found in database 
    // if the email pops up more than once then user will be prompted to login again
	if (result.length != 1) {
        var html = `
        <h2> Invalid email/password combination.</h2>
        <a href='/login'><h2> try again </h2></a>`;
        res.send(html);
		return;
	}
    // if email found then compare the given password to stored password
    // if passwords match then redirect user to members page
	if (await bcrypt.compare(password, result[0].password)) {

		req.session.authenticated = true;
		req.session.email = email;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
    }
    // if email exists but passwords dont match then prompt user to login again.
	else {
        var html = `
        <h2> Incorrect password.</h2>
        <a href='/login'><h2> try again </h2></a>`;
        res.send(html);
		return;
	}
});

// creating a page for users to signup
app.get('/signup', (req,res) => {
    var html = `
    <h2> create user </h2>
    <form action = '/signupSubmit' method = 'post'>
    <input name = 'username' type = 'text' placeholder = 'username'><br>
    <input name = 'email' type = 'email' placeholder = 'email'><br>
    <input name = 'password' type = 'password' placeholder = 'password'><br>
    <button>Submit</button>
    </form>`;
    res.send(html);
});

// action that happens when new user is create
app.post('/signupSubmit', async(req,res) => {
    // parse whats taken in from form field
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    // validate that the following fields are completed correctly
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
       var html = `
       <h1> ${error}. </h1>
       <a href='/signup'><h2> Try again </h2></a>`;
       res.send(html);
	   return;
   }

    // check if email already exists in the user collection
    var existingUser = await userCollection.findOne({ email: email });

    if (existingUser) {
        var html = `
            <h1> This email already exists. </h1>
            <a href='/signup'><h2> Try again </h2></a>`;
        res.send(html);
        return;
    }

   // hash the inserted password
    var hashedPassword = await bcrypt.hash(password, saltRounds);

    // add the new user to collection of users in database
	await userCollection.insertOne({username: username, email: email, password: hashedPassword});

   // redirect to members page if passes validation code
   res.redirect('/members');

});

// members area page
app.get('/members', (req,res) => {

        // local variable to hold username of current session
        var username = req.session.username;

        var html = `
        <h2> Hello ${username}! </h2>`
        res.send(html);

});

// page that represents a user is logged out
app.get('/logout', (req, res) => {
    // destroy current session
    req.session.destroy();

    // redirect to home page
    res.redirect('/');
});


// about page
app.get('/about', (req,res) => {

    // variable to hold the queried color
    var color = req.query.color;

    res.send("<h1 style='color:"+color+";'>Gursidh Sandhu</h1>");
});

// cars page
app.get('/car/:id', (req,res) => {

    // create car variable to hold in queried id
    var car = req.params.id;

    // display certain car based on id

    if(car == 1){
        res.send("<img src='/C6-GIF.gif' style='width:1400px;'>");
    }
    else if(car == 2){
        res.send("<img src='/C7-GIF.webp' style='width:1400px;'>");
    } 
    else if(car == 3){
        res.send("<img src='/C8-GIF.webp' style='width:1400px;'>");
    } 
    else {
        res.send("Invalid car ID");
    }
});

// using the direct path of public folder
app.use(express.static(__dirname + "/public"));

// catch any page that does not exist and make it a 404 page
app.get("*", (req,res) => {
    res.status(404);
    res.send("Page is not found or does not exist - 404");
});
    

