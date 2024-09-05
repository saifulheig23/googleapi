import { Router } from "express";
import validateRequest from "../../middlewares/validateRequest";
import {
  createUserValidationSchema,
  loginValidationSchema,
} from "../user/user.validation";
import { authController } from "./auth.controller";

const authRouter = Router();

authRouter.post(
  "/signup",
  validateRequest(createUserValidationSchema),
  authController.userSignUp
);

authRouter.post(
  "/login",
  validateRequest(loginValidationSchema),
  authController.userLogin
);

authRouter.post("/verify-otp", authController.verifyLoginOtp);

authRouter.post("/forgot-password", authController.forgotPassword);
authRouter.patch("/reset-password/:token", authController.resetPassword);

authRouter.get("/google", authController.googleLogin);

export default authRouter;
