import { boolean, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { Users } from "./user.schema";

export const applicationInfo = pgTable("application_info", {
    year: text("year").notNull(),
    major: text("major").notNull(),
    allergies: text("allergies").notNull(),
    userId: uuid("user_id").references(() => Users.id, {
        onDelete: "cascade"
    }).unique(),
    createdAt: timestamp("created_at").notNull().defaultNow(),
})

