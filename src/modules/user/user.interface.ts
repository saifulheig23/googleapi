/* eslint-disable no-unused-vars */
import { Model } from "mongoose";
import { USER_ROLE } from "./user.constant";

export type TUser = {
  _id: string;
  name: string;
  email: string;
  password: string;
  phone?: string;
  address?: string;
  role: "admin" | "user";
  avatar?: string;
  otp: string;
  otpExpiry: number;

  passwordResetToken: string | undefined;
  passwordResetTokenExpiry: Date | undefined;
  createPasswordResetToken(): string;
};

export type TUserLogin = {
  email: string;
  password: string;
};

export type TUserRole = keyof typeof USER_ROLE;

export interface TUserModel extends Model<TUser> {
  passwordResetTokenExpiry: Date;
  passwordResetToken: string;
  isUserExist(email: string): Promise<TUser>;
  saveOtp(email: string, otp: string, otpExpiry: number): Promise<void>;
  getOtpData(email: string): Promise<TUser>;
  removeOtpData(email: string): Promise<void>;

  createPasswordResetToken(): Promise<void>;
}
