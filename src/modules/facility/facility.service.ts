import { TFacility } from "./facility.interface";
import { Facility } from "./facility.model";

// create facility
const createFacility = async (payload: TFacility) => {
  const result = await Facility.create(payload);
  return result;
};

// get all facilities
const getAllFacilities = async () => {
  const result = await Facility.find({ isDeleted: false });
  return result;
};

// get a single facility
const getSingleFacility = async (id: string) => {
  const result = await Facility.findById(id);
  return result;
};

// update a facility
const updateFacility = async (id: string, payload: TFacility) => {
  const result = await Facility.findByIdAndUpdate(id, payload);
  return result;
};

// soft delete facility
const deleteFacility = async (id: string) => {
  const result = await Facility.findByIdAndUpdate(id, { isDeleted: true });
  return result;
};

export const facilityService = {
  createFacility,
  getAllFacilities,
  getSingleFacility,
  updateFacility,
  deleteFacility,
};
