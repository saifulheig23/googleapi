import bcrypt from "bcrypt";
import crypto from "crypto";
import httpStatus from "http-status";
import jwt from "jsonwebtoken";
import { config } from "../../config";
import apiError from "../../utils/apiError";
import { sendEmail } from "../../utils/sendEmail";
import { TUser, TUserLogin } from "../user/user.interface";
import { User } from "../user/user.model";
import { generateOTP } from "./auth.utils";

//**  sign up user **//
const userSignUp = async (payload: TUser) => {
  // check if user already exist
  const isUserExist = await User.isUserExist(payload.email);
  if (isUserExist) {
    throw new apiError(httpStatus.BAD_REQUEST, "Email already exists");
  }

  // create the user
  const result = await User.create(payload);

  // send response without password
  const userResponse = {
    ...result.toObject(),
    password: undefined,
  };
  delete userResponse.password;

  return userResponse;
};

//* log in user without OTP *//
// const userLogin = async (payload: TUserLogin) => {
//   // check if user exist
//   const isUserExist = await User.isUserExist(payload.email);
//   if (!isUserExist) {
//     throw new apiError(httpStatus.NOT_FOUND, "Email not registered");
//   }

//   // check if password is correct
//   const isPasswordCorrect = await bcrypt.compare(
//     payload?.password,
//     isUserExist?.password
//   );
//   if (!isPasswordCorrect) {
//     throw new apiError(httpStatus.BAD_REQUEST, "Incorrect password");
//   }

//   //? if all ok --> grant access. send access token, refresh token
//   const jwtPayload = {
//     email: isUserExist.email,
//     role: isUserExist.role,
//   };

//   // create jwt access token
//   const accessToken = jwt.sign(jwtPayload, config.jwt_access_secret as string, {
//     expiresIn: config.jwt_access_expires_in as string,
//   });

//   // create jwt refresh token
//   const refreshToken = jwt.sign(
//     jwtPayload,
//     config.jwt_refresh_secret as string,
//     { expiresIn: config.jwt_refresh_expires_in as string }
//   );

//   return {
//     isUserExist,
//     accessToken,
//     refreshToken,
//   };
// };

//** login user with OTP  **/
const userLogin = async (payload: TUserLogin) => {
  const isUserExist = await User.isUserExist(payload.email);
  if (!isUserExist) {
    throw new apiError(httpStatus.NOT_FOUND, "Email not registered");
  }

  const isPasswordCorrect = await bcrypt.compare(
    payload?.password,
    isUserExist?.password
  );
  if (!isPasswordCorrect) {
    throw new apiError(httpStatus.BAD_REQUEST, "Incorrect password");
  }

  // Generate OTP for login verification
  const { otp, expiry } = generateOTP();
  await User.saveOtp(isUserExist.email, otp, expiry);

  // Send OTP to user's email
  await sendEmail({
    to: isUserExist.email,
    subject: "OTP Verification",
    html: `
        <html lang="en" >
    <head>
      <meta charset="UTF-8">
    </head>
    <body>
    <div style="font-family: Helvetica,Arial,sans-serif;overflow:auto;line-height:2">
      <div style="margin:30px auto;width:90%;padding:20px 0">
        <div style="border-bottom:1px solid #eee">
        </div>
        <p style="font-size:1.1em">Hi,</p>
        <p>Use the following OTP to login. OTP is valid for 5 minutes.</p>
        <h2 style="background: #00466a;margin: 0 auto;width: max-content;padding: 0 10px;color: #fff;border-radius: 4px;">${otp}</h2>
        <p style="font-size:0.9em;">Regards,<br />Book My Play</p>
        <hr style="border:none;border-top:1px solid #eee" />
      </div>
    </div>
    </body>
    </html>
        `,
  });

  return {
    message: "OTP sent to email. Please verify to login.",
  };
};

//* Verify OTP during login *//
const verifyLoginOtp = async (payload: Partial<TUser>) => {
  const { email, otp } = payload;

  const isUserExist = await User.isUserExist(payload.email as string);
  // const userOtpData = await User.getOtpData(email as string);
  const { otp: storedOtp, otpExpiry } = isUserExist;

  if (!otp) {
    throw new apiError(httpStatus.BAD_REQUEST, "Please enter the OTP to login");
  }
  if (storedOtp !== otp || Date.now() > otpExpiry) {
    throw new apiError(httpStatus.BAD_REQUEST, "Invalid or expired OTP");
  }

  // Generate JWT tokens
  const jwtPayload = {
    email: isUserExist.email,
    role: isUserExist.role,
  };

  const accessToken = jwt.sign(jwtPayload, config.jwt_access_secret as string, {
    expiresIn: config.jwt_access_expires_in as string,
  });

  const refreshToken = jwt.sign(
    jwtPayload,
    config.jwt_refresh_secret as string,
    { expiresIn: config.jwt_refresh_expires_in as string }
  );

  // Clean up OTP entry
  await User.removeOtpData(email as string);

  return {
    isUserExist,
    accessToken,
    refreshToken,
  };
};

//** forgot password **/
const forgotPassword = async (email: string, hostUrl: string) => {
  const user = await User.findOne({ email: email });
  if (!user) {
    throw new apiError(httpStatus.NOT_FOUND, "Email not registered");
  }

  //? 2. generate a random reset token
  const resetToken = user.createPasswordResetToken();

  await user.save({ validateBeforeSave: false });

  //? 3. Send the token back to the user email
  const resetUrl = `${hostUrl}/reset-password/${resetToken}`;

  await sendEmail({
    to: user.email,
    subject: "Password change request received",
    html: `
    <html lang="en" >
    <head>
      <meta charset="UTF-8">
    </head>
    <body>
    <div style="font-family: Helvetica,Arial,sans-serif;overflow:auto;line-height:2">
      <div style="margin:30px auto;width:90%;padding:20px 0">
        <div style="border-bottom:1px solid #eee">
        </div>
        <p style="font-size:1.1em">Hi,</p>
        <p>We have received a password reset request. Please use the below link to reset your password.</p>
        
        <p><a href=${resetUrl} target="_blank">Reset Password </a></p>
        
        <p>This reset password link will be valid only for 10 minutes. </p>
        
        <p style="font-size:0.9em;">Regards,<br />Book My Play</p>
        <hr style="border:none;border-top:1px solid #eee" />
      </div>
    </div>
    </body>
    </html>
    `,
  });

  return {
    message: "Password reset link sent to email. Please check your email",
  };
};

// ** reset password **/
const resetPassword = async (payload: Record<string, unknown>) => {
  //? 1. If the user exists with the given token & token has not expired
  // hash params token to match DB hashed token
  const token = crypto
    .createHash("sha256")
    .update(payload.token as string)
    .digest("hex");

  //
  const user = await User.findOne({
    passwordResetToken: token,
    passwordResetTokenExpiry: { $gt: Date.now() },
  });

  if (!user) {
    throw new apiError(
      httpStatus.BAD_REQUEST,
      "The token is invalid or has expired!"
    );
  }

  //? 2. resetting user password

  user.password = payload.password as string;
  user.passwordResetToken = undefined;
  user.passwordResetTokenExpiry = undefined;
  user.save();

  return {
    message: "Password reset successfully. Please log in",
  };
};

export const authService = {
  userSignUp,
  userLogin,
  verifyLoginOtp,
  forgotPassword,
  resetPassword,
};
