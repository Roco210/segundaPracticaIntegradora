import { Router } from "express";
import passport from "passport";

const router=Router()

router.get('/current',passport.authenticate('jwt',{session:false, failureRedirect: '/login'}),async (req,res)=>
{
    res.status(200).json({User:req.user.user})

})

export default router;