// express module
const express = require('express');

// express-session module
const session = require('express-session');

// bcrypt module
const bcrypt = require('bcrypt');

const saltRounds = 12;

// run on PORT variable or 3020
const port = process.env.PORT || 3000;

// variable to use express module
const app = express();

// allows us to use parsed data from form to request body
app.use(express.urlencoded({extended:false}));

// variable that encrypts session id
const node_session_secret = '1edc58e3-f3ec-4fdb-be5b-d6a9b041f61c';

// using sessions
app.use(session({
    secret: node_session_secret,
    saveUnitialized: false,
    resave: true
}
));

var users = [];

// creating a home page for users to either click login or signup
app.get('/', (req,res) => {
    var html = `
    <h1> Welcome to Gursidh's Website!</h1>
    <h2> Click login or if you are not a member then click signup:</h2>
    <a href='/login'><button>Login</button></a><br>
    <a href='/signup'><button>Signup</button></a>`;
    res.send(html);
});

// creating a page for users to login
app.get('/login', (req,res) => {
    var html = `
    <h2> log in </h2>
    <form action = '/loggingIn' method = 'post'>
    <input name = 'email' type = 'email' placeholder = 'email'><br>
    <input name = 'password' type = 'password' placeholder = 'password'><br>
    <button>Submit</button>
    </form>`;
    res.send(html);
});

// check if the attempt to login is valid or not
app.post('/loggingIn', (req,res) => {
    // local variables to hold current email and password
    var email = req.body.email;
    var password = req.body.password;
    // check against every previous user
    for(i=0; i<users.length;i++){
        if(users[i].email == email){
            if(bcrypt.compareSync(password, users[i].password)){
                res.redirect('/loggedIn');
                return;
            }
        }
    }
    // if no user found then prompt user to login again
    res.redirect('/login');
});

// creating a page for users to signup
app.get('/signup', (req,res) => {
    var html = `
    <h2> create user </h2>
    <form action = '/newUser' method = 'post'>
    <input name = 'username' type = 'text' placeholder = 'username'><br>
    <input name = 'email' type = 'email' placeholder = 'email'><br>
    <input name = 'password' type = 'password' placeholder = 'password'><br>
    <button>Submit</button>
    </form>`;
    res.send(html);
});

// action that happens when new user is create
app.post('/newUser', (req,res) => {
    // parse whats taken in from form field
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;
    // hash the password now so it is not plaint text
    var hashedPassword = bcrypt.hashSync(password, saltRounds);
    // insert into the users array
    users.push({username: username, email: email, password: hashedPassword});
    var usershtml = "";
    for (i = 0; i < users.length; i++) {
        usershtml += "<li>" + users[i].username + ": " + users[i].email + ": " + users[i].password + "</li>";
    }
    var html = "<ul>" + usershtml + "</ul>";
    res.send(html);

});

// creating a page that represents loggedIn user
app.get('/loggedIn', (req,res) => {
    var html = `
    <h2> Hello User </h2>
    <button> Go to Members Area </button><br>
    <a href='/'><button> Logout </button></a>`
    res.send(html);
});

// tells us what port application is running on
app.listen(port, () => {
    console.log("Application is listening to port " + port);
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
    

