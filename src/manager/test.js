import { testModell } from "../dao/models/test.model.js";

class Testmongo {

    async testT(dato){
        try{

            const t= testModell.create(dato)
            return t
        }
        catch(e){error}
    }
}

export const testmongo = new Testmongo()

// const t= testModell.create({