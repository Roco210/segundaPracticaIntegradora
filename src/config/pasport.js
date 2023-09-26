import passport from "passport";
import {Strategy as localStrategy} from "passport-local";
import githubStrategy from "passport-github2";
import { userModel } from "../dao/models/user.model.js";
import { userMongo } from "../manager/user/userManagerMongo.js";
import {compareHash } from "../utils.js";
import { Strategy as JWTstrategy, ExtractJwt} from "passport-jwt";
import { Cookie } from "express-session";





//local strategy 

 passport.use("local", new localStrategy(
    {usernameField: "email"},
    async (email, password, done) => {
        try {
            const userDb = await userMongo.findUser(email)
            if (!userDb) {
                return done(null, false)
            } 
            const passwordCheck = await compareHash(password, userDb.password)
            if (!passwordCheck) {
                return done(null, false)
            }
            return done(null, userDb)
        }
        catch (error) { done(error) }
    }))


// github strategy
 
passport.use(new githubStrategy(
    {clientID: 'Iv1.a5948c138fda0bf0',
    clientSecret: 'f241c801c0b2e3229f46eb5fe5dd929882a6f2d9',
    callbackURL:'http://localhost:8080/api/user/github'},
    async function (accessToken, refreshToken, profile, done) {
            try {
                const userbd = await userMongo.findUser(profile._json.email)
                if(userbd){
                    return done(null, userbd)
                } 
                const newUser={
                    first_name:profile.displayName? profile.displayName.split(" ")[0]:profile.username,
                    last_name: profile.displayName? profile.displayName.split(" ")[1]: " no lastname",  
                    username: profile.username, 
                    email: profile._json.email? profile._json.email: "no mail",
                    password: " ", 
                    githubLog:"true"}
                await userMongo.createUser(newUser)
                return  done(null, newUser)}
            catch(error){done(error)}}
))


// JWT strategy
const SECRET_KEY = 'secretKey'
const cookieExtractor =  (req) => {
    const cook=req.cookies["token"]
    return cook

}

passport.use("jwt",new JWTstrategy({
    secretOrKey:"secretKey",
    jwtFromRequest: ExtractJwt.fromExtractors([cookieExtractor])
},
    async (jwt_payload, done) => {
        try {
            return done(null, jwt_payload)
        }
        catch (error) { done(null, false) }
    })) 


//serial and deserial User
passport.serializeUser((user, done) => {
    done(null, user);
        });
    
    passport.deserializeUser(async (id, done) => {
        try {
            const user= await userModel.findOne(id)
            done(null, user);
        }
        catch (error) { done(error)}
        });
    


