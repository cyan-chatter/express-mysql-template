const dbrootpass = process.env.DBROOTPASS||'thunder7'

const db = mysql.createConnection({
    host     : 'localhost',
    user     : 'root',
    password : dbrootpass 
    //,database : 'ovsdevdb1'
})

db.connect((err) => {
    if(err){
        throw err
    }
    console.log('MySql Connected')
})

module.exports = db