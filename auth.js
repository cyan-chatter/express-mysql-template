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
    const student = this
    const token = jwt.sign({_id: student._id.toString()},secretKey)
    student.tokens = student.tokens.concat({token})
    await student.save()
    return token 
}

const prepasswordsave = async function(next){
    const student = this
    if(student.isModified('password')){
        student.password = await bcrypt.hash(student.password, 8)
    }
    next()
}

const findByCredentials = async (email, password) =>{
    const student = await Student.findOne({ email })
    
    if(!student){
        throw new Error('E-mail not registered')
    }
    const isMatch = await bcrypt.compare(password, student.password)
    
    if(!isMatch){
        throw new Error('Incorrect Password')
    }

    return student
}


const auth = (type)=>{

    return async(req, res, next)=>{
        try{ 
            const token = req.cookies.token
            const decoded = jwt.verify(token, secretKey)
            let user;
            if(type === 'students'){
                user = await Student.findOne({_id: decoded._id, 'tokens.token':token})
            }
            else if(type === 'teachers'){
                user = await Teacher.findOne({_id: decoded._id, 'tokens.token':token})
            }
            else if(type === 'admins'){
                user = await Admin.findOne({_id: decoded._id, 'tokens.token':token})
            } 
            if (!user) {
            throw new Error()
            }
        req.token = token
        req.user = user
        req.user_type= type
        next()
    
        }catch(e){
            
            res.clearCookie('token','stream','test')

            res.status(401).render('error404',{
                status:'401 :(',
                message: 'Please Authenticate Properly',
                goto: '/',
                destination: 'Home Page'
             })
        }
    }
} 