/* eslint-disable no-unused-vars */
import { ErrorRequestHandler } from "express";
import httpStatus from "http-status";
import mongoose from "mongoose";
import { ZodError } from "zod";
import { config } from "../config";
import { IErrorSource } from "../interface/error";
import ApiError from "../utils/apiError";

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const globalErrorHandler: ErrorRequestHandler = (err, req, res, next) => {
  let statusCode = 500;
  let message = "Something went wrong!";
  let errorSource: IErrorSource = [
    {
      path: "",
      message: "",
    },
  ];

  if (err instanceof ZodError) {
    statusCode = httpStatus.BAD_REQUEST;
    message = "Zod validation error";
    errorSource = err?.issues?.map((issue) => {
      return {
        path: issue?.path[issue.path.length - 1],
        message: issue.message,
      };
    });
  } else if (err?.name === "ValidationError") {
    statusCode = httpStatus.BAD_REQUEST;
    message = "Mongoose Validation error";
    errorSource = Object.values(err?.errors).map((val) => {
      const error = val as
        | mongoose.Error.ValidatorError
        | mongoose.Error.CastError;
      return {
        path: error?.path,
        message: error?.message,
      };
    });
  } else if (err?.name === "CastError") {
    const error = err as mongoose.Error.CastError;
    statusCode = httpStatus.BAD_REQUEST;
    message = " Invalid id, Cast Error";
    errorSource = [
      {
        path: error?.path,
        message: error?.message,
      },
    ];
  } else if (err?.code === 11000) {
    statusCode = httpStatus.CONFLICT;
    message = "Duplicate entry error";
    const match = err.message.match(/"([^"]*)"/);
    const extractedMessage = match && match[1];
    errorSource = [
      {
        path: "",
        message: `${extractedMessage} is already exists`,
      },
    ];
  } else if (err instanceof ApiError) {
    statusCode = err?.statusCode;
    message = err?.message;
    errorSource = [
      {
        path: "",
        message: err?.message,
      },
    ];
  } else if (err instanceof Error) {
    message = err?.message;
    errorSource = [
      {
        path: "",
        message: err?.message,
      },
    ];
  }

  //?ultimate return
  return res.status(statusCode).json({
    success: false,
    message,
    errorSource,
    // myError: err,
    errorStack: config.node_env === "development" ? err?.stack : "",
  });
};

export default globalErrorHandler;
