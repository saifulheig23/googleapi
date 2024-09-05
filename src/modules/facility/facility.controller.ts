import httpStatus from "http-status";
import apiResponse from "../../utils/apiResponse";
import asyncHandler from "../../utils/asyncHandler";
import { facilityService } from "./facility.service";

// create a facility
const createFacility = asyncHandler(async (req, res) => {
  const result = await facilityService.createFacility(req.body);

  apiResponse(res, httpStatus.OK, "Facility added successfully", result);
});

// get all facilities
const getAllFacilities = asyncHandler(async (req, res) => {
  const result = await facilityService.getAllFacilities();

  apiResponse(res, httpStatus.OK, "Facilities retrieved successfully", result);
});

// get single facility
const getSingleFacility = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const result = await facilityService.getSingleFacility(id);

  apiResponse(
    res,
    httpStatus.OK,
    "Single Facility retrieved successfully",
    result
  );
});

// update a facility
const updateFacility = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const result = await facilityService.updateFacility(id, req.body);

  apiResponse(res, httpStatus.OK, "Facility updated successfully", result);
});

// soft delete facility
const deleteFacility = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const result = await facilityService.deleteFacility(id);

  apiResponse(res, httpStatus.OK, "Facility deleted successfully", result);
});

export const facilityController = {
  createFacility,
  getAllFacilities,
  getSingleFacility,
  updateFacility,
  deleteFacility,
};
