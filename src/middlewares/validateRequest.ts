import { AnyZodObject } from "zod";
import asyncHandler from "../utils/asyncHandler";

const validateRequest = (schema: AnyZodObject) => {
  return asyncHandler(async (req, res, next) => {
    await schema.parseAsync(req.body);
    next();
  });
};

export default validateRequest;
