import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import globalErrorHandler from "./middlewares/globalErrorHandler";
import notFound from "./middlewares/notFound";
import authRouter from "./modules/auth/auth.route";
import { bookingController } from "./modules/booking/booking.controller";
import bookingRouter from "./modules/booking/booking.route";
import facilityRouter from "./modules/facility/facility.route";
const app = express();

// middlewares
app.use(cors({
  origin: [
    "http://localhost:5173",
    "https://sports-facility-booking-platform-client-khaki.vercel.app",
    "https://sports-facility-booking-platform-client-766j.vercel.app",
  ],
 credentials: true,
})
);
app.use(express.json());
app.use(cookieParser());

app.get("/", (req, res) => {
  res.send("⚙️ Server is running...");
});

// application routes
app.get("/api/check-availability", bookingController.checkAvailability);
app.use("/api/auth", authRouter);
app.use("/api/facility", facilityRouter);
app.use("/api/bookings", bookingRouter);

// global error handler
app.use(globalErrorHandler);
// not found route
app.use(notFound);

export default app;
