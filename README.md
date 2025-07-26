# 🩸 LifeFlow Blood Donation Server

<div align="center">

[![GitHub stars](https://img.shields.io/github/stars/CodesWithRakib/lifeflow-blood-donation-server?style=for-the-badge)](https://github.com/CodesWithRakib/lifeflow-blood-donation-server/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/CodesWithRakib/lifeflow-blood-donation-server?style=for-the-badge)](https://github.com/CodesWithRakib/lifeflow-blood-donation-server/network)
[![GitHub issues](https://img.shields.io/github/issues/CodesWithRakib/lifeflow-blood-donation-server?style=for-the-badge)](https://github.com/CodesWithRakib/lifeflow-blood-donation-server/issues)
[![npm version](https://img.shields.io/npm/v/lifeflow-blood-donation-server?style=for-the-badge)](https://npmjs.com/package/lifeflow-blood-donation-server) <!-- TODO:  Confirm package name -->


**The robust backend API powering LifeFlow, a blood donation platform.**

</div>

## 📖 Overview

This repository contains the backend server for LifeFlow, a MERN application facilitating blood donations.  The API provides secure, role-based access to manage donation requests, a blog, user accounts, and integrates with Stripe for payment processing.  It's designed for scalability and maintainability, employing best practices for modern Node.js development.  The target audience includes developers working on the LifeFlow project and those interested in learning about a production-ready Node.js backend.

## ✨ Features

- **User Authentication:** Secure user authentication using JWT (JSON Web Tokens).
- **Role-Based Access Control (RBAC):**  Different user roles (e.g., admin, donor, recipient) have varying permissions.
- **Donation Request Management:**  Create, update, and manage blood donation requests.
- **Blog Management:**  Create, edit, and delete blog posts.
- **Stripe Payment Integration:**  Secure payment processing through Stripe.
- **Email Notifications:**  Send email notifications to users and administrators.
- **Data Validation:**  Robust data validation to ensure data integrity.
- **Error Handling:**  Comprehensive error handling for a smooth user experience.


## 🛠️ Tech Stack

**Backend:**

- [![Node.js](https://img.shields.io/badge/Node.js-Black?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)
- [![Express.js](https://img.shields.io/badge/Express.js-404040?style=for-the-badge&logo=express&logoColor=white)](https://expressjs.com/)
- [![MongoDB](https://img.shields.io/badge/MongoDB-%234ea94b?style=for-the-badge&logo=mongodb&logoColor=white)](https://www.mongodb.com/)
- [![JSON Web Token](https://img.shields.io/badge/JWT-Black?style=for-the-badge&logo=json-web-token&logoColor=white)](https://jwt.io/)
- [![Nodemailer](https://img.shields.io/badge/nodemailer-Black?style=for-the-badge&logo=nodemailer&logoColor=white)](https://nodemailer.com/)
- [![Stripe](https://img.shields.io/badge/Stripe-Black?style=for-the-badge&logo=stripe&logoColor=white)](https://stripe.com/)


## 🚀 Quick Start

### Prerequisites

- Node.js (version specified in `package.json`)
- MongoDB (running instance, configuration details in `.env`)


### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/CodesWithRakib/lifeflow-blood-donation-server.git
   cd lifeflow-blood-donation-server
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Environment Setup:**  Create a `.env` file based on `.env.example` and configure your environment variables, including database connection string, JWT secret, and Stripe API keys.

4. **Start the server:**
   ```bash
   npm start
   ```

   The server will start on the port specified in your `.env` file (default: 5000).

## 📁 Project Structure

```
lifeflow-blood-donation-server/
├── index.js             // Server entry point
├── routes/              // API routes
│   ├── auth.js
│   ├── blog.js
│   ├── donation.js
│   └── user.js
├── models/              // Database models
│   ├── User.js
│   ├── Blog.js
│   └── Donation.js
├── config/              // Configuration files (if any)
├── middleware/          // Express middleware (e.g., authentication)
├── utils/               // Helper functions
├── .env                 // Environment variables
├── .env.example         // Example environment variables
├── package.json         // Project dependencies
├── package-lock.json    // Dependency lock file
└── vercel.json          // Vercel deployment config
```

## ⚙️ Configuration

The server is configured primarily through environment variables in the `.env` file.  See `.env.example` for a template.  Key variables include:

- `MONGODB_URI`: MongoDB connection string.
- `JWT_SECRET`: Secret key for JWT generation.
- `STRIPE_SECRET_KEY`: Stripe secret key.
- `STRIPE_PUBLISHABLE_KEY`: Stripe publishable key.
- `EMAIL_USER`: Email username for sending notifications.
- `EMAIL_PASS`: Email password for sending notifications.  


## 📚 API Reference

The API utilizes standard RESTful principles.  Detailed API documentation will be added later. TODO: Add Swagger/OpenAPI documentation.

### Authentication

JWT is used for authentication.  Endpoints for registration and login will be documented separately. TODO:  Add authentication endpoint details.

## 🤝 Contributing

Contributions are welcome! Please see the [CONTRIBUTING.md](CONTRIBUTING.md) file for details.  TODO: Create CONTRIBUTING.md.


## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


---

<div align="center">

**Made with ❤️ by CodesWithRakib**

</div>
