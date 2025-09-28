import { boolean, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";

export const Users = pgTable("users", {
  id: uuid("id").primaryKey().unique().notNull().defaultRandom(),
  name: text("name").notNull(),
  // TODO: make this lowercase
  imageUrl: text("image_url").notNull().default(""),

  email: text("email").notNull().unique(),
  isEmailVerified: boolean("is_email_verified").notNull().default(false),

  passwordHash: text("password_hash"),
  isTemporaryPassword: boolean("is_temporary_password").default(false),

  googleId: text("google_id").unique(),

  createdAt: timestamp("created_at").notNull().defaultNow(),

  isAdmin: boolean("is_admin").notNull().default(false),

});


export type User = typeof Users.$inferSelect;
export type InsertUser = typeof Users.$inferInsert;

export type UserNoPassword = Omit<User, "password_hash">;
