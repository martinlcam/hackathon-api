import { sql } from "drizzle-orm";
import {
  text,
  timestamp,
  pgTable,
  uuid,
  boolean,
  varchar,
} from "drizzle-orm/pg-core";
import { Users } from "./user.schema";

export const Sessions = pgTable("sessions", {
  id: uuid("id")
    .primaryKey()
    .unique()
    .notNull()
    .default(sql`gen_random_uuid()`),

  userId: uuid("user_id")
    .notNull()
    .references(() => Users.id),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  expiresAt: timestamp("expires_at").notNull(),

  /** No idea what this does. */
  isActive: boolean("is_active").notNull().default(true),

  forceExpire: boolean("force_expire").notNull().default(false),
  reasonForceExpire: text("reason_force_expire").default(""),

  ipAddress: varchar("ip_address", { length: 45 }).notNull(),
});

export type Session = typeof Sessions.$inferSelect;
export type InsertSession = typeof Sessions.$inferInsert;
