import { Router } from "express";
import {userMongo} from "../manager/user/userManagerMongo.js";
import { hashdata , compareHash,generateToken} from "../utils.js";
import {verifyToken} from "../middlewares/jwt.middleware.js";

import passport from "passport";

const router = Router();

router.post('/', async (req, res) => {
    const { last_name, first_name, email, age, password } = req.body
    if (!last_name || !first_name || !email || !age || !password) {
        res.status(400).json({ messge: "faltan datos" })
        return
    }
    const userExist = await userMongo.findUser(email)
    if (userExist) {
        res.status(400).json({ messge: "plase use other mail" })
        return
    }
    const hashPassword = await hashdata(password)
    const user = await userMongo.createUser({...req.body,password:hashPassword})
    res.status(200).json({ message: `user created: ${user}` })
    
}
)



/* router.post('/login', async (req, res) => {
    const { email, password } = req.body
    if (!email || !password) {
        res.status(400).json({ messge: "faltan datos" })
    }
    const userExist = await userMongo.findUser(email)
    if (!userExist) {
        res.status(400).json({ messge: "Some data is wrong" })
    }
    const checkPassword = await compareHash(password, userExist.password)
    if (!checkPassword) {
        res.status(400).json({ messge: "Some data is wrong" })
    }
    const token =  generateToken(userExist)
    console.log(token)
    res.cookie("cookieToken", token, {httpOnly:true,secure:true,maxAge:60*60}).status(200).redirect("/index")
})   */
 
router.get("/validation",passport.authenticate('jwt',{session:false}), async(req,res)=>{

    res.status(200).redirect("/index")  
})


router.post('/login', passport.authenticate('local',{failureRedirect:"/",session:false}), 
(req, res) => { 
    const token =  generateToken(req.user)
    res.cookie("token", token, {httpOnly:true,maxAge:60*60*1000}).status(200).redirect("/index")})



router.get('/logout', async (req, res) => {
    req.session.destroy()
    res.clearCookie("token").redirect("/")
})


router.get("/githubSingUp",passport.authenticate('github', { scope: [ 'user:email' ] },{session:false}))

router.get("/github", passport.authenticate('github', { failureRedirect: '/login' },{session:false},),
    async (req, res) => {
        
        res.redirect("/index")
    
})
export default router;
