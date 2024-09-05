import { z } from "zod";

export const createUserValidationSchema = z.object({
  name: z.string({
    required_error: "Name is required.",
    invalid_type_error: "Name must be a string.",
  }),
  email: z
    .string({
      required_error: "Email is required.",
      invalid_type_error: "Email must be a string.",
    })
    .email("Invalid email address."),
  password: z.string({
    required_error: "Password is required.",
    invalid_type_error: "Password must be a string.",
  }),
  phone: z
    .string({
      required_error: "Phone number is required.",
      invalid_type_error: "Phone number must be a string.",
    })
    .optional(),
  address: z
    .string({
      required_error: "Address is required.",
    })
    .optional(),
  role: z
    .enum(["admin", "user"], {
      required_error: "Role is required.",
      invalid_type_error: "Role must be either 'admin' or 'user'.",
    })
    .default("user"),
  avatar: z.string().optional(),
});

export const loginValidationSchema = z.object({
  email: z
    .string({
      required_error: "Email is required.",
      invalid_type_error: "Email must be a string.",
    })
    .email("Invalid email address."),
  password: z.string({
    required_error: "Password is required.",
    invalid_type_error: "Password must be a string.",
  }),
});
