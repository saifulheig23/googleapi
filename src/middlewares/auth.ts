import httpStatus from "http-status";
import jwt, { JwtPayload } from "jsonwebtoken";
import { config } from "../config";
import { TUserRole } from "../modules/user/user.interface";
import { User } from "../modules/user/user.model";
import apiError from "../utils/apiError";
import asyncHandler from "../utils/asyncHandler";

const auth = (...user_role: TUserRole[]) => {
  return asyncHandler(async (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
      throw new apiError(httpStatus.UNAUTHORIZED, "Unauthorize Access");
    }

    // verify token
    const decoded = jwt.verify(
      token,
      config.jwt_access_secret as string
    ) as JwtPayload;

    // check if user exist
    const isUserExist = await User.isUserExist(decoded.email);
    if (!isUserExist) {
      throw new apiError(httpStatus.NOT_FOUND, "User not found");
    }

    // check user role
    if (user_role && !user_role.includes(isUserExist.role)) {
      throw new apiError(httpStatus.FORBIDDEN, "Forbidden Access");
    }

    req.user = decoded as JwtPayload;
    next();
  });
};

export default auth;
