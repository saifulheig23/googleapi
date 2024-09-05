import { Response } from "express";

const apiResponse = <T>(
  res: Response,
  statusCode: number,
  message: string,
  data: T
): Response => {
  return res.status(statusCode).json({
    success: true,
    statusCode: statusCode || 200,
    message: message,
    data: data,
  });
};

export default apiResponse;
