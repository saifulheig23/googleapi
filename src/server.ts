/* eslint-disable no-console */
import { Server } from "http";
import app from "./app";
import { config } from "./config";
import connectDB from "./DB";

const port = config.port || 5000;
let server: Server;

connectDB()
  .then(() => {
    server = app.listen(port, () => {
      console.log(`🌐 Server is running on port ${port}`);
    });
  })
  .catch((err) => {
    console.log(`❌ Database connection error: ${err}`);
  });

// Handle unhandled promise rejections
process.on("unhandledRejection", (reason, promise) => {
  console.log(`😈 unhandledRejection is detected at ${promise}, ${reason}`);
  if (server) {
    server.close(() => {
      process.exit(1);
    });
  } else {
    process.exit(1);
  }
});
