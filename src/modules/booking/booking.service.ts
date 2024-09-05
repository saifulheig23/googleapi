import httpStatus from "http-status";
import jwt, { JwtPayload } from "jsonwebtoken";
import { config } from "../../config";
import apiError from "../../utils/apiError";
import { Facility } from "../facility/facility.model";
import { USER_ROLE } from "../user/user.constant";
import { User } from "../user/user.model";
import { TBooking } from "./booking.interface";
import { Booking } from "./booking.model";
import { getAvailableTimeSlots, getTimeDifference } from "./booking.utils";

// create a booking
const createBooking = async (token: string, payload: TBooking) => {
  const { startTime, endTime, date } = payload;

  if (!token) {
    throw new apiError(httpStatus.UNAUTHORIZED, `Unauthorize Access`);
  }

  // verify token
  const decoded = jwt.verify(
    token,
    config.jwt_access_secret as string
  ) as JwtPayload;

  // check if the email is registered or not
  const user = await User.findOne({ email: decoded.email });
  if (!user) {
    throw new apiError(httpStatus.NOT_FOUND, "User not found");
  }

  // check if the user role
  if (user?.role !== USER_ROLE.user) {
    throw new apiError(httpStatus.FORBIDDEN, "Forbidden access");
  }

  // check if the facility is exists
  const facility = await Facility.findById(payload.facility);
  if (!facility) {
    throw new apiError(httpStatus.NOT_FOUND, "Facility not found");
  }

  //* Check if the slot is already booked for that day *//
  const selectedDate = date || new Date().toISOString().split("T")[0];

  // check if there is already a booking  on that day
  const existingBooking = await Booking.findOne({
    date: selectedDate,
    facility: facility,
    $or: [{ startTime: { $lt: endTime }, endTime: { $gt: startTime } }],
  });

  if (existingBooking) {
    throw new apiError(
      httpStatus.BAD_REQUEST,
      "The requested time slot is already booked. Please choose another time."
    );
  }

  //* calculate time *//
  const totalTime = getTimeDifference(startTime, endTime);

  //* calculate payable amount *//
  const facilityPrice = facility?.pricePerHour;
  const payableAmount = totalTime * facilityPrice;

  // create booking object
  const bookingData: TBooking = {
    ...payload,
    payableAmount,
    user: user?.id,
    isBooked: "unconfirmed",
  };

  const result = await Booking.create(bookingData);
  return result;
};

// view all bookings (Admin only)
const viewAllBookings = async () => {
  const result = await Booking.find().populate("facility").populate("user");

  return result;
};

// view bookings by user email
const viewUserBookings = async (token: string) => {
  if (!token) {
    throw new apiError(httpStatus.UNAUTHORIZED, `Unauthorize Access`);
  }

  // verify token
  const decoded = jwt.verify(
    token,
    config.jwt_access_secret as string
  ) as JwtPayload;

  // check if the email is registered or not
  const user = await User.findOne({ email: decoded.email });
  if (!user) {
    throw new apiError(httpStatus.NOT_FOUND, "User not found");
  }

  const result = await Booking.find({ user: user?._id }).populate("facility");
  return result;
};

// cancel a booking by user
const cancelBooking = async (token: string, id: string) => {
  if (!token) {
    throw new apiError(httpStatus.UNAUTHORIZED, `Unauthorize Access`);
  }

  // verify token against access token
  const decoded = jwt.verify(
    token,
    config.jwt_access_secret as string
  ) as JwtPayload;

  const user = await User.findOne({ email: decoded.email });
  if (!user) {
    throw new apiError(httpStatus.NOT_FOUND, "User not found");
  }

  const booking = await Booking.findById(id);

  if (!booking) {
    throw new apiError(httpStatus.NOT_FOUND, "Booking not found");
  }

  // check if user has access to this booking
  if (user?.id !== booking.user.toString()) {
    throw new apiError(
      httpStatus.FORBIDDEN,
      "Forbidden access. This is not your booking"
    );
  }

  const result = await Booking.findByIdAndUpdate(
    id,
    { isBooked: "cancelled" },
    { new: true }
  );
  return result;
};

// check availability of time slots
const checkAvailability = async (payload: Partial<TBooking>) => {
  const { date, startTime, endTime } = payload;

  const selectedDate =
    date ||
    new Date()
      .toLocaleString("en-CA", { timeZone: "Asia/Dhaka" })
      .split(",")[0];

  // Retrieve bookings for the specified date
  const bookings = await Booking.find({ date: selectedDate });

  // Generate and calculate available time slots
  const availableSlots = getAvailableTimeSlots(
    bookings,
    startTime || "08:00",
    endTime || "24:00",
    120
  );

  return availableSlots;
};

export const bookingService = {
  createBooking,
  viewAllBookings,
  viewUserBookings,
  cancelBooking,
  checkAvailability,
};
