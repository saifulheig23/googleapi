import mongoose from "mongoose";
import { TBooking } from "./booking.interface";

const bookingSchema = new mongoose.Schema<TBooking>(
  {
    date: {
      type: String,
      required: true,
    },
    startTime: {
      type: String,
      required: true,
    },
    endTime: {
      type: String,
      required: true,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    facility: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Facility",
      required: true,
    },
    payableAmount: {
      type: Number,
      required: true,
    },
    isBooked: {
      type: String,
      enum: ["confirmed", "unconfirmed", "cancelled"],
      default: "unconfirmed",
    },
  },
  { timestamps: true }
);

export const Booking = mongoose.model<TBooking>("Booking", bookingSchema);
