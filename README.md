# Sbenz Club Website

A web application for the Sbenz Club with user authentication, admin panel, and invite system.

## Features

- User registration and login system
- Admin dashboard for user management
- Invite code system
- Profile management
- Payment integration (2Checkout and Crypto)
- Responsive design

## Prerequisites

- Node.js (version 14 or higher)
- npm (comes with Node.js)
- MongoDB database

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ivor213/sbenz-club-website.git
   cd sbenz-club-website
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Set up environment variables:**
   Create a `.env` file in the root directory with the following variables:
   ```
   MONGO_URI=your_mongodb_connection_string
   JWT_SECRET=your_jwt_secret_key
   ```

4. **Start the server:**
   ```bash
   node benz-club/server.js
   ```

5. **Access the application:**
   Open your browser and go to `http://localhost:3000`

## Project Structure

```
sbenz-club-website/
├── benz-club/
│   ├── public/
│   │   ├── assets/
│   │   │   ├── css/
│   │   │   ├── js/
│   │   │   └── fonts/
│   │   ├── index.html
│   │   ├── admin.html
│   │   ├── profile.html
│   │   ├── shop.html
│   │   └── product-invite.html
│   └── server.js
├── package.json
├── package-lock.json
└── README.md
```

## Available Scripts

- `npm start` - Start the server
- `npm install` - Install dependencies

## Technologies Used

- **Backend:** Node.js, Express.js, MongoDB
- **Frontend:** HTML, CSS, JavaScript
- **Authentication:** JWT, bcrypt
- **Database:** MongoDB with Mongoose
- **Payment:** 2Checkout API, Crypto payments

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is private and proprietary. 