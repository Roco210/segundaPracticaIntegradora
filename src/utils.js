import {dirname} from 'path';
import {fileURLToPath} from 'url';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';


export const __dirname= dirname(fileURLToPath(import.meta.url))

//LINK mongo 
export const URI ="mongodb+srv://rickyfernandez210:123456.@cluster0.ublusye.mongodb.net/ecomerce?retryWrites=true&w=majority"

// hash password
export const hashdata=  async (data)=>{
    return bcrypt.hash(data, 10)
}

export const compareHash = async (data, hash)=>{
    return bcrypt.compare(data, hash)
}

// JWT
const SECRET_KEY = 'secretKey'

export const generateToken = (user) => {
    const token = jwt.sign({user}, SECRET_KEY, { expiresIn: '24h' })
    return token
}

