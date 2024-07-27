import express from "express"
import axios from  "axios"
import mongoose from "mongoose"
import { schema , investors , founders , data } from "./db";
import cors from "cors"
const startups = mongoose.model("data" , schema , "devsquare");

const app = express()
app.use(express.json())
app.use(cors())

app.get("/data" , async(req, res) =>{
  try{
    console.log("received request");
    const investorz = await investors.find({})
    const founderz = await founders.find({})
    res.json({
      investors : investorz,
      founders : founderz
    })
  }
  catch(e) {
    console.error("Error getting data !" , e)
    res.send(false)
  }
})

app.get("/startups" , async (req , res) =>{
  try {
  
    const resp = await startups.find()
    
    console.log(resp);
    res.json(resp);
  } catch (e) {
    console.error("An error occurred:", e);
    res.status(500).send(false);
  }
})
// app.get("/edit" , async (req,res)=>{
//   try{
//     const resp = await startups.updateMany({
//       image : "https://firebasestorage.googleapis.com/v0/b/chatapp-4deee.appspot.com/o/ProfilePics%2Fdefault-pic.jpg?alt=media&token=8edde63e-f164-44b4-a1c2-6e912f2fd76b"
//     })
//   }
//   catch{
//     console.error("Error updating data!")
//   }
// })

app.listen(3000)