import { z } from "zod";

export const facilityValidationSchema = z.object({
  name: z.string().min(1, { message: "Name is required and cannot be empty." }),

  description: z
    .string()
    .min(1, { message: "Description is required and cannot be empty." }),

  pricePerHour: z
    .number()
    .positive({ message: "Price per hour must be a positive number." })
    .min(0.01, { message: "Price per hour must be greater than zero." }),

  location: z
    .string()
    .min(1, { message: "Location is required and cannot be empty." }),

  isDeleted: z.boolean().optional(), // Optional since it has a default value in Mongoose

  imageUrl: z
    .string()
    .min(1, { message: "image url is required and cannot be empty." }),
});

export const updateFacilityValidationSchema = z.object({
  name: z
    .string()
    .min(1, { message: "Name is required and cannot be empty." })
    .optional(),

  description: z
    .string()
    .min(1, { message: "Description is required and cannot be empty." })
    .optional(),

  pricePerHour: z
    .number()
    .positive({ message: "Price per hour must be a positive number." })
    .min(0.01, { message: "Price per hour must be greater than zero." })
    .optional(),

  location: z
    .string()
    .min(1, { message: "Location is required and cannot be empty." })
    .optional(),

  isDeleted: z.boolean().optional(),
});
