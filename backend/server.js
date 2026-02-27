const express= require('express');
const dotenv=require('dotenv');
const cors=require('cors');
const connectDB=require("./config/db");
const useragent=require('express-useragent');
const app=express();

dotenv.config();
//middelware
app.use(cors());
app.use(express.json());


//connectin data base 
connectDB();
//adding useragent middleware
app.use(useragent.express());
//routes
app.use('/api/auth', require('./routes/auth'))




//starting the server
const PORT=process.env.PORT|| 5000;
app.listen(PORT,()=>{
    console.log(`server started at port${PORT}`);

});
