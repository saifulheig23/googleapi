import { Router } from "express";
import auth from "../../middlewares/auth";
import validateRequest from "../../middlewares/validateRequest";
import { USER_ROLE } from "../user/user.constant";
import { bookingController } from "./booking.controller";
import { bookingValidationSchema } from "./booking.validation";

const bookingRouter = Router();

bookingRouter.post(
  "/",
  auth(USER_ROLE.user),
  validateRequest(bookingValidationSchema),
  bookingController.createBooking
);

bookingRouter.get(
  "/",
  auth(USER_ROLE.admin),
  bookingController.viewAllBookings
);

bookingRouter.get(
  "/user",
  auth(USER_ROLE.user),
  bookingController.viewUserBookings
);

bookingRouter.delete(
  "/:id",
  auth(USER_ROLE.user),
  bookingController.cancelBooking
);

export default bookingRouter;
