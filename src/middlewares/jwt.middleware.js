import jwt from 'jsonwebtoken';

const SECRET_KEY = 'secretKey'
export const verifyToken = (req,res,next) => {
    const verifyHader = req.headers.authorization;
    if(!verifyHader){
        return res.status(401).json({message: 'Unauthorized 1'
    })}
    const token = verifyHader.split(' ')[1]
    const userData =jwt.verify(token, SECRET_KEY)
    req.user = userData.user
    next()}
    