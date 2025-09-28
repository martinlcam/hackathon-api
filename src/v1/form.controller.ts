import { db, getFirst } from "@lib/db";
import { Body, Get, Post, Put, Request, Route, Security, Delete } from "tsoa";
import { applicationInfo } from "@app/schema/applicationInfo";
import { eq } from "drizzle-orm";

type Form = {
    year: string;
    major: string;
    allergies: string;
}

async function submitForm(userId: string, formData: Form) {
    await db.insert(applicationInfo).values({
        year: formData.year,
        major: formData.major,
        allergies: formData.allergies,
        userId: userId,
    })
}

async function deleteForm(userId: string) {
    await db.delete(applicationInfo)
        .where(eq(applicationInfo.userId, userId))
}


async function updateForm(userId: string, formData: Form) {
    await db.update(applicationInfo).set
        ({
            year: formData.year,
            major: formData.major,
            allergies: formData.allergies,
        })
        .where(eq(applicationInfo.userId, userId))
}

@Route("v1/form")
export class FormController {
    @Post()
    @Security("jwt")
    async submitForm(
        @Body() body: Form,
        @Request() request: Express.Request
    ) 
    
    {
        const user = request.user!;
        await submitForm(user.id, body)
        return "Form sucesfully submitted"
    }

    @Get()
    @Security("jwt")
    public async getOwnForm(
        @Request() request: Express.Request
    ) {
        const user = request.user!;
        const result = await db.select().from(applicationInfo)
            .where(eq(applicationInfo.userId, user.id))
            .then(getFirst)
        return result
    }

    @Put()
    @Security("jwt")
    async updateForm(
        @Body() body: Form,
        @Request() request: Express.Request) {
        const user = request.user!;
        await updateForm(user.id, body)

        return "Form succesfully updated"
    }

    @Delete()
    @Security("jwt")
    async deleteForm(
        @Request() request: Express.Request) {
        const user = request.user!;
        await deleteForm(user.id)

        return "Form succesfully deleted"
    }



}

/*crud
create
read
update
delete*/

/*get route for getting application that exsists already by user id
update app by userid */

/*Recieve form from frontend, pull out userid, update form with the same userid*/
