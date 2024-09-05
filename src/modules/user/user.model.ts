import bcrypt from "bcrypt";
import crypto from "crypto";
import mongoose from "mongoose";
import { config } from "../../config";
import { TUser, TUserModel } from "./user.interface";

const userSchema = new mongoose.Schema<TUser, TUserModel>(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
    phone: {
      type: String,
      // required: true,
    },
    address: {
      type: String,
      // required: true,
    },
    role: {
      type: String,
      enum: ["admin", "user"],
      default: "user",
    },
    avatar: {
      type: String,
    },

    otp: {
      type: String, // Field to store OTP
      default: null,
    },
    otpExpiry: {
      type: Number, // Field to store OTP expiry time
      default: null,
    },

    passwordResetToken: {
      type: String,
    },
    passwordResetTokenExpiry: {
      type: Date,
    },
  },
  { timestamps: true }
);

// hash password before saving
userSchema.pre("save", async function (next) {
  this.password = await bcrypt.hash(
    this.password,
    Number(config.bcrypt_salt_round)
  );
  next();
});

// clear password
userSchema.post("save", async function (doc, next) {
  doc.password = "";
  next();
});

// static methods
userSchema.statics.isUserExist = async function (email) {
  return await User.findOne({ email: email });
};

userSchema.statics.saveOtp = async function (email, otp, expiry) {
  // Save OTP to database with email, otp, and expiry
  return await this.updateOne({ email }, { otp, otpExpiry: expiry });
};

userSchema.statics.getOtpData = async function (email) {
  // Retrieve OTP data from database
  return await this.findOne({ email }, { otp: 1, otpExpiry: 1 });
};

userSchema.statics.removeOtpData = async function (email) {
  // Remove OTP data from database
  return await this.updateOne({ email }, { $unset: { otp: 1, otpExpiry: 1 } });
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");

  // Hash token
  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");
  this.passwordResetTokenExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  return resetToken;
};

export const User = mongoose.model<TUser, TUserModel>("User", userSchema);
