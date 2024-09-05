// import mongoose from "mongoose";
// import { TOtpVerification, TOtpVerificationModel } from "./otpVerification.interface";

// const otpVerificationSchema = new mongoose.Schema<TOtpVerification, TOtpVerificationModel>(
//   {
//     email: {
//       type: String,
//     },
//     otp: {
//       type: String,
//       default: null
//     },
//     otpExpiry: {
//       type: Number,
//       default: null
//     },
//   },
//   {
//     timestamps: true,
//   }
// );


// otpVerificationSchema.statics.saveOtp = async function (email, otp, expiry) {
//   // Save OTP to database with email, otp, and expiry
//   return await this.updateOne({ email }, { otp, otpExpiry: expiry });
// };

// otpVerificationSchema.statics.getOtpData = async function (email) {
//   // Retrieve OTP data from database
//   return await this.findOne({ email }, { otp: 1, otpExpiry: 1 });
// };

// otpVerificationSchema.statics.removeOtpData = async function (email) {
//   // Remove OTP data from database
//   return await this.updateOne({ email }, { $unset: { otp: 1, otpExpiry: 1 } });
// };




// //  OtpVerification model
// export const OtpVerification = mongoose.model<TOtpVerification, TOtpVerificationModel>(
//   "OtpVerification",
//   otpVerificationSchema
// );