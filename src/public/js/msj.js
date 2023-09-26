const socketClient = io("http://localhost:8080");

const form1= document.getElementById("form");
const name1= document.getElementById("nombre");
const inputmessage= document.getElementById("message");
const chat1= document.getElementById("chat");

let usuario

Swal.fire({
    title: 'Bienvenido',
    text: 'Ingresa tu correo',
    input: 'text',
    inputValidator:(value)=>{
      if(!value){return 'Necesitas ingresar tu nombre'}

    }
  }).then(nombre=>{
    usuario =nombre.value
    console.log(usuario)
    name1.innerText=`Hola ${usuario}`

  })

  form1.onsubmit=(e)=>{
    e.preventDefault()
    const msj ={
      user:usuario,
      message :inputmessage.value
    }
  
    socketClient.emit("msj",msj)

  }

  socketClient.on("msjs",async(listmsjs)=>{
    const list= listmsjs.map(e=>{
      return `<p>${e.user}</p>: <p>${e.message}</p>`
    })
    chat1.innerHTML =list
  })


