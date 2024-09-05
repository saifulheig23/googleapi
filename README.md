# Level-2 Assignment-3
## Sports Facility Booking Platform (Backend)

## Installation

To install the application, follow these steps:

1. **Clone the repository:**

   ```bash
   git clone https://github.com/RagibShariar/level-2-assignment-2.git
   ```

2. **Install the dependencies:**

   ```bash
   npm install
   ```

## Running the Application

To run the application locally, follow these steps:

1. Ensure you are in the project directory.
2. Compile the TypeScript code:

```sh
   npm run build
```

3. Start the application:

```sh
   npm run start
```

4. Open your web browser and go to:

```sh
   http://localhost:5000
```

## Configuration

The application requires a configuration file to connect to the MongoDB database and set up other environment variables. Here’s how you can set up your configuration:

1. Create a .env file in the root directory.
2. Add the following environment variables in the .env file:

### .env

```sh
NODE_ENV=development
PORT=5000
MONGODB_URI=Your_MongoDB_URI
BCRYPT_SALT_ROUND=
DEFAULT_PASSWORD=
JWT_ACCESS_SECRET=
JWT_ACCESS_EXPIRES_IN=7d
JWT_REFRESH_SECRET=
JWT_REFRESH_EXPIRES_IN=14d
```

## User Routes - API Endpoints

### **1. User Sign Up**
- **Endpoint**: **`/api/auth/signup`**
- **Method:** `POST`
- **Request Body:** 
```json
{
  "name": "Programming Hero",
  "email": "web@programming-hero.com",
  "password": "programming-hero",
  "phone": "01322901105",
  "role": "admin", // or 'user'
  "address": "Level-4, 34, Awal Centre, Banani, Dhaka"
}
```

  
### **2. User Login**
- **Endpoint**: **`/api/auth/login`**
- **Method:** `POST`
- **Request Body:** 
```json
{
  "email": "web@programming-hero.com",
  "password": "programming-hero"
}
```

## Facility Routes - API Endpoints
### **1. Create a Facility (Admin Only)**
- **Endpoint**: **`/api/facility`**
- **Method:** `POST`
- **Headers:** `Authorization: Bearer JWT_TOKEN`
- **Request Body:** 
```json
{
  "name": "Tennis Court",
  "description": "Outdoor tennis court with synthetic surface.",
  "pricePerHour": 30,
  "location": "456 Sports Ave, Springfield"
}
```
  

### **2. Update a Facility (Admin Only)**
- **Endpoint**: **`/api/facility/:id`**
- **Method:** `PUT`
- **Headers:** `Authorization: Bearer JWT_TOKEN`

### **3. Delete a Facility - Soft Delete (Admin Only)**
- **Endpoint**: **`/api/facility/:id`**
- **Method:** `DELETE`
- **Headers:** `Authorization: Bearer JWT_TOKEN`

### **4. Get All Facilities**
- **Endpoint**: **`/api/facility`**
- **Method:** `GET`

## Booking Routes - API Endpoints

### **1. Check Available Time Slots**
- **Endpoint**: **`/api/check-availability`**
- **Endpoint**: **`/api/check-availability?date=2024-08-13`**
- **Method:** `GET`

### **2. Create a Booking (User Only)**
- **Endpoint**: **`/api/bookings`**
- **Method:** `POST`
- **Headers:** `Authorization: Bearer JWT_TOKEN`
- **Request Body:** 
```json
{
  "facility": "60d9c4e4f3b4b544b8b8d1c5",
  "date": "2024-06-15",
  "startTime": "10:00",
  "endTime": "13:00"
}
```


### **3. View All Bookings (Admin Only)**
- **Endpoint**: **`/api/bookings`**
- **Method:** `GET`
- **Headers:** `Authorization: Bearer JWT_TOKEN`


### **4. View Bookings by User (User Only)**
- **Endpoint**: **`/api/bookings/user`**
- **Method:** `GET`
- **Headers:** `Authorization: Bearer JWT_TOKEN`


### **2. Cancel a Booking (User Only)**
- **Endpoint**: **`/api/bookings/:id`**
- **Method:** `DELETE`
- **Headers:** `Authorization: Bearer JWT_TOKEN`