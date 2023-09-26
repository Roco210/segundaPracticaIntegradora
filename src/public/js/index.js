const socketClient = io();
const prodRealTime= document.getElementById("realTimeProds");



socketClient.on('allProds',(data)=>{
    
    const allprods = data.map((e)=>{
        return  `<h1>Title: ${e.title}</h1><p> Description: ${e.description}</p><p>Code: ${e.code}</p><p>Price: ${e.price}</p>
        <p>Stock: ${e.stock}</p><p>Category: ${e.category}</p><p>Id: ${e._id}</p>`
        });
    prodRealTime.innerHTML =allprods

});


