import { Router } from "express";
import auth from "../../middlewares/auth";
import validateRequest from "../../middlewares/validateRequest";
import { USER_ROLE } from "../user/user.constant";
import { facilityController } from "./facility.controller";
import { facilityValidationSchema } from "./facility.validation";

const facilityRouter = Router();

// create facility
facilityRouter.post(
  "/",
  auth(USER_ROLE.admin),
  validateRequest(facilityValidationSchema),
  facilityController.createFacility
);

// get all facilities
facilityRouter.get("/", facilityController.getAllFacilities);

// get single facility
facilityRouter.get("/:id", facilityController.getSingleFacility);

// update a facility
facilityRouter.put(
  "/:id",
  auth(USER_ROLE.admin),
  facilityController.updateFacility
);

// delete a facility
facilityRouter.delete(
  "/:id",
  auth(USER_ROLE.admin),
  facilityController.deleteFacility
);

export default facilityRouter;
