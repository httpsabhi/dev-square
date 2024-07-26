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
  try{
    const resp = await startups.findOne({
      name : "SlyakaOfficial",
    })
    console.log(resp)
    res.json({
      name : resp?.name,
      founders : resp?.founders,

    })
  }
  catch(e) {
    res.send(false)
  }
})
app.get

app.listen(3000)