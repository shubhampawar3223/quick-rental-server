const express = require('express');
const app = express();
const mongodb = require('mongodb');
require('dotenv').config(); 
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const mongoClient = mongodb.MongoClient;
const dbUrl = process.env.DB_URL ||  'mongodb://127.0.0.1:27017';
const port = process.env.PORT || 5200;


app.use(express.json());
app.use(cors());

app.post('/signup',async (req,res)=>{
    try{
     let clientInfo = await mongoClient.connect(dbUrl);
     let db = clientInfo.db('app');
     let find = await db.collection('users').findOne({email:req.body.email});
     if(!find){
         let salt = await bcrypt.genSalt(10);
         let hash = await bcrypt.hash(req.body.password,salt);
         req.body.password= hash; 
         await db.collection('users').insertOne(req.body);
         res.status(200).json({message:"User is creates."}) 
     }
     else{
        res.status(400).json({message:"User already present."});
     }
    }
    catch(e){
        console.log(e);
    }
})

app.post('/login',async(req,res)=>{
   try{
    let clientInfo = await mongoClient.connect(dbUrl);
    let db = clientInfo.db('app');
    let find = await db.collection('users').findOne({email:req.body.email});
    if(find){
       let verify = await bcrypt.compare(req.body.password,find.password);
       if(verify){
        let token = await jwt.sign(
            {user_id: find._id, role:find.role},
            process.env.JWT_KEY  )   
        res.status(200).json({message:"Login Success", token: token, role:find.role});
       }
       else{
        res.status(400).json({message:"User incorrect password."}); 
       }
    }else{
        res.status(404).json({message:"User not found."});               
    }
   }
   catch(e){
   console.log(e);
   }
})

app.post('/add-products',[authenticate,isValidRole("admin")],async(req,res)=>{
    try{
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db('app');
        let find = await db.collection('products').findOne({product_id:req.body.id});
        if (find){
            res.status(400).json({message:"Already present"})
        }else{
        await db.collection('products').insertOne(req.body);
        res.status(200).json({message:"product added"});
        }
    }
    catch(e){
       console.log(e);
    }

})

app.post('/update-product',[authenticate,isValidRole("admin")],async(req,res)=>{
    try{
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db('app');
        await db.collection('products').findOneAndUpdate({product_id:req.body.product_id},{$set:
            {
                "name":req.body.name,
                "photo":req.body.photo,
                "category":req.body.category,
                "Description": req.body.Description,
                "charges": req.body.charges,
                "status": req.body.status,
                "deposit": req.body.deposit
            }});
        res.status(200).json({message:"Update is successful."})        
    }
    catch(e){
       console.log(e);
    }

})

app.post('/delete-product',[authenticate,isValidRole("admin")],async(req,res)=>{
    try{
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db('app');
        await db.collection('products').deleteOne({product_id:req.body.product_id});
        res.status(200).json({message:"Deleted successfully."})        
    }
    catch(e){
       console.log(e);
    }

})

app.get('/get-categories',authenticate,async(req,res)=>{
    try{
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db('app');
        let categories = await db.collection('products').distinct("category");
        res.status(200).json({message:"Success.", categories: categories})        
    }
    catch(e){
       console.log(e);
    }

})

app.get('/products',authenticate,async (req,res)=>{
    try{
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db('app');
        let products = await db.collection('products').find().project({ownerName:0, mobNo:0, emailId:0}).toArray();
        res.status(200).json({message:"Success.", products: products})        
    }
    catch(e){
       console.log(e);
    }
})

app.get('/product-info/:id',authenticate,async(req,res)=>{
    try{
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db('app');
        let product = await db.collection('products').findOne({id: req.params.id});
        res.status(200).json({message:"Success.", product: product})        
    }
    catch(e){
       console.log(e);
    }
})

//api for admin to get active enquiry on console.
app.post('/enquiry',[authenticate,isValidRole("admin")],async(req,res)=>{
    try{
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db('app');
        let queries = await db.collection('enquiry').find({status:"active"}).toArray();
        res.status(200).json({message:"successfull.", queries: queries})        
    }
    catch(e){
       console.log(e);
    }

})

//API for admin so that he can acknowledge the query.
app.post('/enquiry-acknowledged',[authenticate,isValidRole("admin")],async(req,res)=>{
    try{
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db('app');
         await db.collection('enquiry').findOneAndUpdate({id:req.body.id},{$set:{status:"inactive"}});
        res.status(200).json({message:"successfull."})        
    }
    catch(e){
       console.log(e);
    }

})

///user side API's
//API for user enquiry
app.post('/enquiry',async(req,res)=>{
    try{
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db('app');
        await db.collection('enquiry').insertOne(req.body);
        res.status(200).json({message:"successfull."})        
    }
    catch(e){
       console.log(e);
    }

})

//app.post('/purchse',async())
app.get('/',[authenticate,isValidRole("user")],(req,res)=>{
    res.send({message:"Hello"});
})

//authentiction function
function authenticate(req, res, next){
    if(req.headers.authorisation !== undefined){
      jwt.verify(
          req.headers.authorisation, 
          process.env.JWT_KEY,
          (err,decode)=>{
              if(decode !== undefined){
                req.role = decode.role;
               next();
              }
              else{
                res.status(401).json({message: 'No Authorisation toke.'});           
              }
          })
    }
    else{
       res.status(401).json({message: 'No Authorisation toke.'}); 
    }
}

//role validation authentication
function isValidRole(role){
  return function(req,res,next){
    if(req.role && req.role === role){
       next();
   }
   else{
       res.send(403);
   }
}
}

app.listen(port , ()=>{console.log("server is listening on port:"+ port)});
