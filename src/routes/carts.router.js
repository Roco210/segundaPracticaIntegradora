import { Router } from "express";
import { cartMongo } from "../manager/cart/cartManagerMongo.js";

const router = Router()

router.post("/", async (req, res) => {

    try {
        await cartMongo.getCarts()
        res.status(200).json({ mesage: 'Cart created' })
    }
    catch (error) { res.status(500).json({ error }) }
}
)

router.get("/:cid", async (req, res) => {
   let cid = req.params.cid
   if(cid.length!=24){
    res.status(400).json({mesage:"Put a correct Id"})
    return
   }
   try{
    const cart = await cartMongo.getCartById(cid)
    if(!cart || cart.name== "CastError"){
        res.status(400).json({mesage:`no exist a cart whith id ${cid}`})
    }else {res.status(200).json(cart)}
   }
   catch (error){ res.status(500).json({ error }) }
})

router.post("/:cid/product/:pid", async (req, res) => {
    let cid = req.params.cid
    let pid = req.params.pid
    try{
    if(cid.length!=24){
        res.status(400).json({mesage:"Put a correct Cart Id"})
        return
    }if(pid.length!=24){
        res.status(400).json({mesage:"Put a correct Prod Id"})
        return
    }
    const cartUpdate = await cartMongo.updatecart(cid,pid)
    if(cartUpdate=="cart update"){res.status(200).json(cartUpdate)  }
    else{
        res.status(400).json({mesage:cartUpdate})
    }
     }
    catch (error){ res.status(500).json({ error }) }
})

/* router.delete("/:cid", async (req, res) => {
    let cid = req.params.cid
    if(cid.length!=24){
     res.status(400).json({mesage:"Put a correct Id"})
     return
    }
    try{
     const del = await cartMongo.deleteCart(cid)
     if(!del || del.name== "CastError"){
         res.status(400).json({mesage:`no exist a cart whith id ${cid}`})
     }else {res.status(200).json({mesage:"cart deleted"})}
    }
    catch (error){ res.status(500).json({ error }) }
 }) */

router.delete('/:cid/product/:pid',async(req,res)=>{
    
    try{
        const t=await cartMongo.delProdCart(cid,pid)

        res.status(200).json({t})
    }
    catch(error){ res.status(500).json({ error }) }
})
router.delete('/:cid', async(req,res)=>{
    const {cid} = req.params 
    const delProds=await cartMongo.delAllprods(cid)
    res.status(200).json({delProds})

})



router.put('/:cid/product/:pid', async(req,res)=>{
    const {cid,pid} = req.params
    const cant = req.body
    try{const t=await cartMongo.putquantity(cid,pid,cant)
    res.status(200).json({mensage:'se actualizo el prod'})}

    catch(error){ res.status(500).json({ error }) }
})


router.put('/:cid', async (req,res)=>{
    const {cid} = req.params
    const prod = req.body
    try{const t=await cartMongo.putProd(cid,prod)
        res.status(200).json({t})}
    catch(error){ res.status(500).json({ error }) }
})


export default router