const mysql = require('mysql');
//database connection
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'hotelnew',
    clearExpired: true,
    autoReconnect: true,
    createDatabaseTable: true, // add this option
    acquireTimeout: 1000000 // optionally add this option if still getting the previous error

  });

  module.exports= connection;  