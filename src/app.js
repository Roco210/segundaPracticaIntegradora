//generic
import express from 'express';
import { __dirname } from "./utils.js";
import cookieParser from 'cookie-parser';
import session from 'express-session';

// dao
import { URI } from './utils.js';
import './dao/dbConfig.js';
import MongoStore from 'connect-mongo';


//handlebars
import { engine } from "express-handlebars";


// server
import { Server } from "socket.io";
import { productMongo } from './manager/product/productManagerMongo.js';
import { msjModel } from './manager//messages/messagesManager.js';


//endpoints
import porductsRouter from './routes/products.router.js';
import cartsRouter from './routes/carts.router.js';
import viewsRouter from "./routes/views.router.js";
import userRouter from './routes/user.router.js';
import sessionsRouter from './routes/sessions.router.js';


// passport
import passport from 'passport';
import './config/pasport.js'



//server
const app = express()
const PORT = 8080
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(__dirname + "/public"));

//handlebars
app.engine('handlebars', engine());
app.set('views', __dirname + '/views');
app.set('view engine', 'handlebars');


//session
app.use(session({
    store: MongoStore.create({
        mongoUrl: URI,
        mongoOptions: { useNewUrlParser: true, useUnifiedTopology: true },
    }),
    secret: "secret"
}))
  
//passport

app.use(passport.initialize());
app.use(passport.session());



//endpoints
app.use('/api/products', porductsRouter);
app.use('/api/carts', cartsRouter);
app.use('/api/user', userRouter);
app.use('/api/sessions', sessionsRouter);
app.use("/", viewsRouter);




//conect
const httpServer = app.listen(PORT, () => {
    console.log(`Escuchando puerto ${PORT}`)
})
const socketServer = new Server(httpServer)

socketServer.on('connection', async (socket) => {
    console.log(`Se conecto ${socket.id}`)
    socket.on('disconnect', () => {
        console.log(`Se desconecto ${socket.id}`)
    })

    const allprod = await fetch('http://localhost:8080/api/products')
    const getProd = await allprod.json()
    const allProds = getProd.payload
    socketServer.emit('allProds', allProds)

    socket.on("msj", async (e) => {
        console.log(e)
        await msjModel.createMsj(e)
        const listmsjs = await msjModel.findMsj()
        socketServer.emit("msjs", listmsjs)
    })
})




