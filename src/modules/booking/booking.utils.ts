import { TBooking } from "./booking.interface";

// calculate the time difference between two times (startTime and endTime)
export const getTimeDifference = (startTime: string, endTime: string) => {
  // Parse the time strings
  const start = new Date(`1970-01-01T${startTime}:00Z`);
  const end = new Date(`1970-01-01T${endTime}:00Z`);

  const differenceInMs = end.getTime() - start.getTime();
  const differenceInMinutes = differenceInMs / (1000 * 60);
  const differenceInHours = differenceInMinutes / 60;

  return differenceInHours;
};

const generateTimeSlots = (
  startTime: string,
  endTime: string,
  slotDuration: number
) => {
  const timeSlots = [];
  let currentStartTime = startTime;

  while (currentStartTime < endTime) {
    let currentEndTime = addMinutes(currentStartTime, slotDuration);
    if (currentEndTime > endTime) {
      currentEndTime = endTime;
    }
    timeSlots.push({ startTime: currentStartTime, endTime: currentEndTime });
    currentStartTime = currentEndTime;
  }

  return timeSlots;
};

// Helper function to add minutes to a time string
const addMinutes = (time: string, minutes: number) => {
  const [hours, mins] = time.split(":").map(Number);
  const totalMinutes = hours * 60 + mins + minutes;
  const newHours = Math.floor(totalMinutes / 60)
    .toString()
    .padStart(2, "0");
  const newMinutes = (totalMinutes % 60).toString().padStart(2, "0");
  return `${newHours}:${newMinutes}`;
};

// to get available time slots by excluding already booked slots
export const getAvailableTimeSlots = (
  bookings: TBooking[],
  startTime: string,
  endTime: string,
  slotDuration: number
) => {
  const availableSlots = generateTimeSlots(startTime, endTime, slotDuration);
  let availableTimes = [...availableSlots];

  bookings.forEach((booking) => {
    availableTimes = availableTimes.flatMap((slot) => {
      if (
        booking.startTime >= slot.endTime ||
        booking.endTime <= slot.startTime
      ) {
        return [slot];
      } else {
        const freeSlots = [];
        if (booking.startTime > slot.startTime) {
          freeSlots.push({
            startTime: slot.startTime,
            endTime: booking.startTime,
          });
        }
        if (booking.endTime < slot.endTime) {
          freeSlots.push({ startTime: booking.endTime, endTime: slot.endTime });
        }
        return freeSlots;
      }
    });
  });

  return availableTimes;
};
