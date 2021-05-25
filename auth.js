const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const secretKey = process.env.JWT_SECRET || 'TotalOverdose'

// app.use((req,res,next)=>{
//     if(req.method === 'GET' || req.method === 'POST' || req.method === 'PATCH' || req.method === 'DELETE'){
//         res.status(503).end('Request Temporarily Disabled. Server is Under Maintainance')
//     } else{
//        next()
//     }
// })

const generateAuthToken = async function (){
    const client = this
    const token = jwt.sign({_id: client._id.toString()},secretKey)
    client.tokens = client.tokens.concat({token})
    //await client.save()
    return token 
}

const prepasswordsave = async function(next){
    const client = this
    if(client.isModified('password')){
        client.password = await bcrypt.hash(client.password, 8)
    }
    next()
}

const findByCredentials = async (email, password) =>{
    
    let client

    //client = await client.findOne({ email })

    if(!client){
        throw new Error('E-mail not registered')
    }
    const isMatch = await bcrypt.compare(password, client.password)
    
    if(!isMatch){
        throw new Error('Incorrect Password')
    }

    return client
}


const auth = (type)=>{
    return async(req, res, next)=>{
        try{ 
            const token = req.cookies.token
            const decoded = jwt.verify(token, secretKey)
            let user;
            //user = await client.findOne({_id: decoded._id, 'tokens.token':token}) 
            if (!user) {
            throw new Error()
            }
        req.token = token
        req.user = user
        req.user_type= type
        next()
        }catch(e){
            res.clearCookie('token')
            res.status(401).send({
                status:'401 :(',
                message: 'Please Authenticate Properly'
             })
        }
    }
} 