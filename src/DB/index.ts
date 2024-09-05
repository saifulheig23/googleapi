/* eslint-disable no-console */
import mongoose from "mongoose";
import { config } from "../config";

const connectDB = async () => {
  try {
    const connectionInstance = await mongoose.connect(`${config.mongodb_uri}`);
    console.log("✅ Database connected: ", connectionInstance.connection.name);
  } catch (error) {
    console.log("❌ Database connection error: ", error);
    process.exit(1);
  }
};

export default connectDB;
