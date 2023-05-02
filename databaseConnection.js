// this file provides the connection to mongoDb database

// use dotenv module
require('dotenv').config();


const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;

// create an instance of a mongodb client
const MongoClient = require('mongodb').MongoClient;

// connect to the database cluster
const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}.rye5pig.mongodb.net/test`;

var database = new MongoClient(atlasURI, {useNewUrlParser: true, useUnifiedTopology: true});
module.exports = {database};
