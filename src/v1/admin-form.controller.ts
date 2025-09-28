import { Body, Get, Post, Put, Request, Route, Security, Delete, Query } from "tsoa";
import { applicationInfo } from "@app/schema/applicationInfo";
import { db, getFirst } from "@lib/db";
import { ErrorBadRequest } from "@lib/status/error";
import { query } from "express";

/* aproove and deny applications, requires admin id for whos
 aprooving.denying, tagging each application aprooved and 
 denied 
 save uid of the applicant*/

/*checks if user is accepted rejected or under review*/

@Route("v1/adminform")
export class AdminFormController 
{
    @Get()
    @Security("jwt")
    public async getPaginatedForms(
        @Request() request: Express.Request,
        @Query("page") page: number
    ) 
    
    {   
        const user = request.user!;
        const isAdmin = user.isAdmin; 
        if (!isAdmin) {
            throw new ErrorBadRequest("You do not have permission to view forms");
        }

        const result = await db.select().from(applicationInfo).limit(10).offset(10 * page-1);
        return result;
    }
}

