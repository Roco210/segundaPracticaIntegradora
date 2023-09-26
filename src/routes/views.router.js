
import { Router } from "express";
import { userMongo } from "../manager/user/userManagerMongo.js";
import MongoStore from "connect-mongo";
import { URI } from '../utils.js';
import passport from "passport";

const router = Router()


router.get('/', async (req, res) => {
    res.render('sesion')
    
});

router.get('/login', async (req, res) => {
    res.render('login');
});

router.get('/index',passport.authenticate('jwt',{session:false,failureRedirect:"/login"}), async (req, res) => {
    const user =  req.user.user
    const admin = user.isAdmin ? "ADMIN":"USER"
    const cook = [{
        first_name: user.first_name,
        rol: admin
    }]
    res.render("index", { cook } );
})


router.get('/allproducts',passport.authenticate('jwt',{session:false, failureRedirect:"/"}), async (req, res) => {
    const user =  req.user
    console.log(user)
    if(!user){
        res.redirect('/login')
    }

    const allprod = await fetch('http://localhost:8080/api/products')
    const getProd = await allprod.json()
    const allProds = getProd.payload
    const allProdMap = allProds.map(e => ({
        _id: e._id,
        title: e.title,
        description: e.description,
        code: e.code,
        price: e.price,
        stock: e.stock,
        category: e.category
    }))
    res.render("home", { allProdMap })
});


router.get('/realTimeProducts',passport.authenticate('jwt',{session:false, failureRedirect:"/"}), (req, res) => {

    res.render('realTimeProducts')
})

router.get('/message', (req, res) => {

    res.render('message')
})

router.get('/cart',passport.authenticate('jwt',{session:false, failureRedirect:"/"}), async (req, res) => {
    const cart = await fetch('http://localhost:8080/api/carts/64f0084c102e954bf361aae0')
    const getCart = await cart.json()
    const allprod = getCart.products
    const allProdMap = allprod.map(e => ({
        prodId: e.prodId,
        quantity: e.quantity
    }))
    res.render('cartId', { allProdMap })
})


router.get('/logout', (req, res) => {
    
})


export default router