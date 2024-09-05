// 4 digit otp generator
export const generateOTP = () => {
  const otp = (Math.floor(1000 + Math.random() * 9000)).toString() ;
  const expiry = Date.now() + 5 * 60 * 1000; // 5 minutes from now
  return { otp, expiry };
};
