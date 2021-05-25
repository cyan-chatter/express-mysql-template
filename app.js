const express = require('express')
const path = require('path')

//let db = require('../dbConnect')
let db = {s : 'testing router'}

const entry = require('./routers/entry')

const port = process.env.PORT||3000

const app = express()

app.use(express.json())

const publicDirectoryPath = path.join(__dirname, '../public')
app.use(express.static(publicDirectoryPath))

app.use(entry(db))

app.get('/', (_, res) => {
    res.send("Welcome to ICast - an API for Online Voting")
})

app.get('*',(_,res)=>{
    res.status(404).send("The Requested Operation is Not Found")
})

app.listen(port, () => {
    console.log('Server is up on port ' + port)
})


