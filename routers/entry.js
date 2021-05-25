const express = require('express')
const mysql = require('mysql')

var createRouter =  function (config){
    var router =  express.Router()
    
    router.get('/entry', (req,res)=>{
        let db = config
        res.send("This will Work: " + db.s)
    })







    return router
}
module.exports = createRouter