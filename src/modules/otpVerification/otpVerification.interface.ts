// /* eslint-disable no-unused-vars */
// import { Model } from "mongoose";

// export type TOtpVerification = {
//   email: string;
//   otp: string;
//   otpExpiry: number;
// };

// export interface TOtpVerificationModel extends Model<TOtpVerification> {
//   saveOtp(
//     email: string,
//     otp: number,
//     expiry: number
//   ): Promise<void>;
//   getOtpData(email: string): Promise<TOtpVerification>;
//   removeOtpData(email: string): Promise<void>;
// }
