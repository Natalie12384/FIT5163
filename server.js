//node -watch server.js 
// this allows auto refresh of server when making edits to code

//server dependencies
const express = require('express'); //pull express library
const path = require("path");
const app = express();
const PORT = 8000;
app.use(express.urlencoded({extended: true}));
app.use(express.json());

//encryption libraries
const bcrypt = require('bcrypt');
//

//databases
users= []

const PATH = path.join(__dirname, "/public/");


app.listen(PORT,function () {
  console.log(`listening on port http://localhost:${PORT}`);
});

app.get('/', function (req, res) {
  fileName = PATH + "login.html";
  res.sendFile(fileName);
});

//create new voter
app.post('/create-user', async function(req, res){
    try{
      const salt = await bcrypt.genSalt() //(length) the longer the salt the more secure = longer time to make it 
      const password = req.body.new_password
      const password_hash = await bcrypt.hash(password, salt)
      console.log(password, salt)
      const username = req.body.new_username
      const user = {username: username, password_hash:password_hash, salt: salt}
      users.push(user);
      console.log(user)
      res.status(200).send(user);
      
    }catch{
      res.status(201).send()
      }
  }
)

//login in existing user
  app.post('/login-user', async function(req, res){
    const user = users.find(user=>user.username = req.body.username)
    if (user == null){
      res.status(400).send('Cannot find user');
    }
    try{
       //more secure to prevent timeing attack by using bcrypt
      if (await bcrypt.compare(req.body.password, user.password_hash)) {
        //create token to send to client server, verifying their identity
        res.redirect('/dashboard');

      }else{
        res.send('not allowed')
      }
    }catch{
      res.status(500).send()
    }
})
//Authentication token?




/**
 * This is all logic in the dashboard page
 * - voting
 * - authentication
 * - blinding???
 */

//get route to dashboard page
app.get('/dashboard/', function (req, res) {
  //authentication logic
  fileName = PATH + "dashboard.html";
  res.sendFile(fileName);
});
//blind vote function
function blind(){

}


/**
 * Signer and verification logic
 * 
 */
//blind signing function
function keygen(){

}
function sign(){
  
}
function verify(){
  
}


