const express = require('express')
const app = express()
const session = require('express-session')
const ejs = require('ejs')
const path = require('path') 
const PORT = process.env.PORT || 9500
// const mysql = require('mysql');
const mysql = require('mysql2');
const flash = require('express-flash')
const connection = require('./db-config')
const validator = require('validator');
const bcrypt = require ('bcrypt')
const passport = require('passport')
const expressLayout =require('express-ejs-layouts')
const cookieParser = require('cookie-parser');
const MySQLStore = require('express-mysql-session')(session);

connection.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL database: ' );
    return;
  }
  console.log('Connected to MySQL database' );
});
const adminRouter = require('./routes/admin')


//session config

const sessionStore = new MySQLStore({}, connection);

app.use(session({
  secret: 'secret',
  resave: false,
  saveUninitialized: false,
  cookie: {maxAge: 1000*60*60*24}, //24hours 86400000 milliseconds
  store: sessionStore
}));


const passportInit = require('./http/passport')
passportInit(passport)
app.use(passport.initialize())
app.use(passport.session())


app.use(express.static('public'))
app.use(express.urlencoded({extended: false}))
app.use(express.json())


app.use(flash())

//set template engine
app.use(expressLayout)
app.set('views',path.join(__dirname,'/views')) //template file location
app.set('view engine','ejs')

app.use(cookieParser());

app.use(adminRouter)

app.listen(PORT, ()=>{
    console.log(`Server is running at port ${PORT} `)
})
