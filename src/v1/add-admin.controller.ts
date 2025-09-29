import { Users } from "@app/schema";
import { db } from "@lib/db";
import { ErrorBadRequest } from "@lib/status/error";
import { eq } from "drizzle-orm";
import { Body, Get, Post, Request, Route, Security } from "tsoa";

type AddAdminBody = { userId: string; }

async function makeAdmin(userId: string) {
    await db.update(Users).set({ isAdmin: true })
        .where(eq(Users.id, userId))
}

@Route("/v1/add-admin")
export class AddAdminController {
    @Post()
    @Security("jwt")
    async addAdmin(
        @Body() body: AddAdminBody,
        @Request() request: Express.Request,
    ) {
        const user = request.user!;
        const isAdmin = user.isAdmin;
        if (!isAdmin) {
            throw new ErrorBadRequest("user is not an admin");
        }

        await makeAdmin(body.userId);
        return "User was sucesfully made Admin"
    }

}





/*post addAdmin (user id input)
verify user that called route is admin
update non admin user to admin status 
let caller know that user was sucesfully updated
drizzle*/