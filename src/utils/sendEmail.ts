/* eslint-disable no-console */
import nodemailer from "nodemailer";
import { config } from "../config";

type TEmailOptions = {
  to: string;
  subject: string;
  html: string;
}

const transporter = nodemailer.createTransport({
  host: config.smtp_host,
  port: Number(config.smtp_port),
  secure: false, // Use `true` for port 465, `false` for all other ports
  auth: {
    user: config.smtp_mail,
    pass: config.smtp_password,
  },
});

export const sendEmail = async (options:TEmailOptions) => {
  
  const emailOptions = {
    from: config.smtp_mail, // sender address
    to: options.to, // list of receivers
    subject: options.subject, // Subject line
    // text: `OTP Verification", Your OTP is: ${otp}` // plain text body
    html: options.html, // html body
  };

  try {
    await transporter.sendMail(emailOptions);
    console.log("✅ Email sent successfully");
  } catch (error) {
    console.error("Error sending email:", error);
    throw new Error("❌ Error sending email");
  }
};
