import httpStatus from "http-status";
import apiResponse from "../../utils/apiResponse";
import asyncHandler from "../../utils/asyncHandler";
import { bookingService } from "./booking.service";

// create a booking (Users only)
const createBooking = asyncHandler(async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1] as string;
  const result = await bookingService.createBooking(token, req.body);

  apiResponse(res, httpStatus.OK, "Booking created successfully", result);
});

// view all bookings (Admin only)
const viewAllBookings = asyncHandler(async (req, res) => {
  const result = await bookingService.viewAllBookings();

  apiResponse(res, httpStatus.OK, "Bookings retrieved successfully", result);
});

// view bookings by user email
const viewUserBookings = asyncHandler(async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1] as string;
  const result = await bookingService.viewUserBookings(token);

  apiResponse(res, httpStatus.OK, "Bookings retrieved successfully", result);
});

// cancel a booking by user
const cancelBooking = asyncHandler(async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1] as string;
  const { id } = req.params;
  const result = await bookingService.cancelBooking(token, id);

  apiResponse(res, httpStatus.OK, "Booking canceled successfully", result);
});

// check availability time
const checkAvailability = asyncHandler(async (req, res) => {
  const availableSlots = await bookingService.checkAvailability(req.query);

  apiResponse(
    res,
    httpStatus.OK,
    "Availability checked successfully",
    availableSlots
  );
});

export const bookingController = {
  createBooking,
  viewAllBookings,
  viewUserBookings,
  checkAvailability,
  cancelBooking,
};
