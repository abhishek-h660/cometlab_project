const express = require('express')
var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");
var cors = require('cors')
const app = express()
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const port = 8080;
require('dotenv').config()
app.use(express.json());

const corsOpts = {
    origin: '*',
  
    methods: [
      'GET',
      'POST',
      'PATCH',
      'UPDATE',
      'DELETE',
    ],
  
    allowedHeaders: [
      'Content-Type',
    ],
};
  
app.use(cors(corsOpts));

const username = process.env.MONGO_USER;
const password = process.env.MONGO_PASS;
const user = encodeURIComponent(username);
const pass = encodeURIComponent(password);

const uri = `mongodb+srv://${user}:${pass}@cluster0.ckxff.mongodb.net/?retryWrites=true&w=majority`

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

const database = client.db("cometlabs")

//collections

function collectionUsers() {
    try{
        return database.collection("users");
    }catch(e){
        console.log("error", e)
    }
}

function collectionProblems() {
    try{
        return database.collection("problems");
    }catch(e){
        console.log("error", e)
    }
}

//APIs

//signup
function signup(user, res) {
    try{
        //if email already exist then returns error
        collectionUsers().findOne({"email": user.email}).then(findRes => {
            if(findRes  == null){
                bcrypt.genSalt(10).then(salt => {
                    return bcrypt.hash(user.password, salt)
                }).then(hash => {
                    user.password = hash
                    collectionUsers().insertOne(user).then(addResult => {
                        const payload = {
                            id: addResult._id,
                            admin: false
                        }
                        if(user.admin){
                            payload.admin = true
                        }
                        const token = jwt.sign(payload, process.env.JWT_SECRET,
                        {
                            algorithm: 'HS256',
                            allowInsecureKeySizes: true,
                            expiresIn: 3600, // 1 hour
                        });
                        const response = {
                            email: user.email,
                            token: token
                        }
                        
                        res.send(response)
                    })
                })
            }else{
                const response = {
                    error: true,
                    message: "email already exists"
                }
                res.send(response)
            }
        })
        
        
    }finally{}
}
//signin
function signin(user, res) {
    try{
        //if email doesnot exist then returns error
        collectionUsers().findOne({"email": user.email}).then(findRes => {
            if(findRes  != null){
                bcrypt.compare(user.password, findRes.password).then(booleanResult => {
                    if(booleanResult){
                        const payload = {
                            id: findRes._id,
                            admin: false
                        }
                        if(findRes.admin){
                            payload.admin = true
                        }
                        const token = jwt.sign(payload, process.env.JWT_SECRET,
                            {
                                algorithm: 'HS256',
                                allowInsecureKeySizes: true,
                                expiresIn: 3600, // 1 hour
                            });
                       
                        const response = {
                            email: findRes.email,
                            token: token
                        }
                        res.send(response)
                    }else{
                        const response = {
                            error: true,
                            message: "invalid credentials"
                        }
                        res.send(response)
                    }
                })
            }else{
                const response = {
                    error: true,
                    message: "invalid credentials"
                }
                res.send(response)
            }
        })
    }finally{}
}

//add problems for admins
function addProblem(problem, res) {
    try{
        
        collectionProblems().insertOne(problem).then(addResult => {
            res.send(addResult)
        })
        
    }finally{}
}

function editProblem(problem, res) {
    try{
        
        collectionProblems().updateOne({"_id": ObjectId.createFromHexString(problem._id)}).then(updateRes => {
            res.send(updateRes)
        })
        
    }finally{}
}

//add problems for admins
function deleteProblem(problem_id, res) {
    try{
        const id = ObjectId.createFromHexString(problem_id)
        collectionProblems().deleteOne({_id: id}).then(deleteResult => {
            res.send(deleteResult)
        })
    }finally{}
}

//middleware
function middleware(token) {
    const payload = jwt.verify(token, process.env.JWT_SECRET)
    return payload.admin
}


//serving routes
app.post('/api/v1/signup', (req, res) => {
    const user = req.body
    signup(user, res)
})

app.post('/api/v1/signin', (req, res) => {
    const user = req.body
    signin(user, res)
})

app.post('/api/v1/addProblem', (req, res) => {
    const token = req.headers.authorization.split(" ")[1]
    const isAdmin = middleware(token)
    if(!isAdmin){
        const response = {
            error: true,
            message: "access denied"
        }
        res.send(response)
    }else{
        const problem = req.body
    addProblem(problem, res)
    }
})

app.patch('/api/v1/editProblem', (req, res) => {
    const token = req.headers.authorization.split(" ")[1]
    const isAdmin = middleware(token)
    if(!isAdmin){
        const response = {
            error: true,
            message: "access denied"
        }
        res.send(response)
    }else{
        const problem = req.body
        editProblem(problem, res)
    }
})

app.delete('/api/v1/deleteProblem/:id', (req, res) => {
    console.log("came 1 ")
    const token = req.headers.authorization.split(" ")[1]
    const isAdmin = middleware(token)
    if(!isAdmin){
        const response = {
            error: true,
            message: "access denied"
        }
        res.send(response)
    }else{
        const problem_id = req.params.id
        deleteProblem(problem_id, res)
    }
   
})

app.listen(port, ()=>{
    console.log(`app is listening at port: ${port}`);
});