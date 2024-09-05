import { z } from "zod";

export const bookingValidationSchema = z.object({
  date: z.string().min(1, { message: "Date is required and cannot be empty." }),

  startTime: z
    .string()
    .min(1, { message: "Start time is required and cannot be empty." }),

  endTime: z
    .string()
    .min(1, { message: "End time is required and cannot be empty." }),

  // user: z
  //   .string()
  //   .min(1, { message: "User ID is required and cannot be empty." }),
  facility: z
    .string()
    .min(1, { message: "Facility ID is required and cannot be empty." }),

  // payableAmount: z
  //   .number()
  //   .positive({ message: "Payable amount must be a positive number." }),

  isBooked: z
    .enum(["confirmed", "unconfirmed", "cancelled"], {
      message:
        "Booking status must be 'confirmed', 'unconfirmed', or 'cancelled'.",
    })
    .optional(), // Optional since it has a default value in Mongoose
});
