import axios from "axios";
import { Request, Response } from "express";
import httpStatus from "http-status";
import jwt from "jsonwebtoken";
import { config } from "../../config";
import apiResponse from "../../utils/apiResponse";
import asyncHandler from "../../utils/asyncHandler";
import { oauth2client } from "../../utils/googleConfig";
import { USER_ROLE } from "../user/user.constant";
import { User } from "../user/user.model";
import { authService } from "./auth.service";

// user sign up
const userSignUp = asyncHandler(async (req, res) => {
  const userData = req.body;
  const result = await authService.userSignUp(userData);

  apiResponse(
    res,
    httpStatus.CREATED,
    "Your account has been created. Please log in",
    result
  );
});

//**  user login  **//
// const userLogin = asyncHandler(async (req, res) => {
//   const result = await authService.userLogin(req.body);
//   const { _id, name, email, role, phone, address } = result.isUserExist;

//   //set refresh token in cookie
//   res.cookie("refreshToken", result.refreshToken, {
//     httpOnly: true,
//     secure: config.node_env === "production",
//   });

//   res.status(httpStatus.OK).json({
//     success: true,
//     statusCode: httpStatus.OK,
//     message: "User logged in successfully",
//     token: result.accessToken,
//     data: {
//       _id,
//       name,
//       email,
//       role,
//       phone,
//       address,
//     },
//   });
// });

//** login user with OTP  **/
const userLogin = asyncHandler(async (req, res) => {
  const result = await authService.userLogin(req.body);

  apiResponse(res, httpStatus.OK, "OTP sent to email", result);
});

//* Verify OTP and  login *//
const verifyLoginOtp = asyncHandler(async (req, res) => {
  const result = await authService.verifyLoginOtp(req.body);
  const { _id, name, email, role, phone, address } = result.isUserExist;

  //set refresh token in cookie
  res.cookie("refreshToken", result.refreshToken, {
    httpOnly: true,
    secure: config.node_env === "production",
  });

  res.status(httpStatus.OK).json({
    success: true,
    statusCode: httpStatus.OK,
    message: "User logged in successfully",
    token: result.accessToken,
    data: {
      _id,
      name,
      email,
      role,
      phone,
      address,
    },
  });
});

//** forgot password **/
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  // const hostUrl = `${req.protocol}://${req.get('host')}`
  const hostUrl = `http://localhost:5173`;

  const result = await authService.forgotPassword(email, hostUrl);

  apiResponse(
    res,
    httpStatus.OK,
    "Password reset link sent to email. Please check your email",
    result
  );
});

// ** reset password **//
const resetPassword = asyncHandler(async (req, res) => {
  const token = req.params.token;
  const password = req.body.password;

  const result = await authService.resetPassword({ token, password });

  apiResponse(
    res,
    httpStatus.OK,
    "Password reset successfully. Please log in",
    result
  );
});

//** google login **//
const googleLogin = async (req: Request, res: Response) => {
  try {
    const { code } = req.query;

    const googleRes = await oauth2client.getToken(code as string);
    oauth2client.setCredentials(googleRes.tokens);

    const userRes = await axios.get(
      `https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${googleRes.tokens.access_token}`
    );

    // console.log("userRes.data:=> ", userRes.data);
    const { email, name, picture } = userRes.data;
    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({
        name,
        email,
        password: "123456",
        avatar: picture,
        role: USER_ROLE.user,
      });
    }
    const { _id, phone, address } = user;

    // generate token
    // Generate JWT tokens
    const jwtPayload = {
      email: user.email,
      role: user.role,
    };

    const accessToken = jwt.sign(
      jwtPayload,
      config.jwt_access_secret as string,
      {
        expiresIn: config.jwt_access_expires_in as string,
      }
    );

    // const refreshToken = jwt.sign(
    //   jwtPayload,
    //   config.jwt_refresh_secret as string,
    //   { expiresIn: config.jwt_refresh_expires_in as string }
    // );

    return res.status(httpStatus.OK).json({
      success: true,
      statusCode: httpStatus.OK,
      message: "Google login successful",
      token: accessToken,
      data: {
        _id,
        name,
        email,
        phone,
        address,
      },
    });
    // eslint-disable-next-line no-unused-vars, @typescript-eslint/no-unused-vars
  } catch (error) {
    // console.error(error); // Log the error for debugging
    return res.status(500).json({
      message: "Error while requesting google code",
    });
  }
};

export const authController = {
  userSignUp,
  userLogin,
  verifyLoginOtp,
  forgotPassword,
  resetPassword,
  googleLogin,
};
