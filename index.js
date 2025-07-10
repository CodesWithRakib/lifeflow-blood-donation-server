require("dotenv").config();
const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
const nodemailer = require("nodemailer");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 5000;

// ====== Middleware Setup ======
const corsOptions = {
  origin: ["http://localhost:5173"], // you can allow multiple origins if needed
  credentials: true,
  methods: ["GET", "POST", "PATCH", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// ====== Nodemailer Setup ======
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ====== JWT Middleware ======

const verifyJWT = (req, res, next) => {
  const token = req.cookies?.jwt;
  if (!token) {
    return res
      .status(401)
      .json({ message: "Unauthorized access. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    req.decoded = decoded;
    next();
  } catch (error) {
    return res
      .status(403)
      .json({ message: "Forbidden access. Invalid token." });
  }
};

// ====== Admin Role Check ======
const verifyAdmin = async (req, res, next) => {
  try {
    const user = await usersCollection.findOne({ email: req.userEmail });
    if (!user || user.role !== "admin") {
      return res.status(403).json({ success: false, message: "Admin only" });
    }
    next();
  } catch (err) {
    console.error("verifyAdmin error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// ====== MongoDB Client Setup ======
const client = new MongoClient(process.env.DB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let usersCollection,
  donationRequestCollection,
  blogsCollection,
  fundingCollection;

const allowedStatuses = ["active", "blocked", "inactive"];
const allowedRoles = ["donor", "volunteer", "admin"];

async function run() {
  try {
    await client.connect();
    const db = client.db("bloodDonationApp");
    usersCollection = db.collection("users");
    donationRequestCollection = db.collection("donationRequest");
    fundingCollection = db.collection("funds");
    blogsCollection = db.collection("blogs");

    // ====== AUTH ROUTES ======
    app.post("/jwt", (req, res) => {
      const { email } = req.body;
      if (!email) return res.status(400).json({ message: "Email required" });

      const token = jwt.sign({ email }, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "7d",
      });

      res
        .cookie("jwt", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production", // ✅ HTTPS-only in prod
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict", // ✅ CORS-safe
          maxAge: 7 * 24 * 60 * 60 * 1000, // ⏰ Good to add explicit expiration (7 days)
        })
        .json({ message: "JWT set", token });
    });

    // ====== Stripe Checkout Session (Optional) ======
    app.post("/create-checkout-session", async (req, res) => {
      const { amount } = req.body;
      try {
        const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          line_items: [
            {
              price_data: {
                currency: "bdt",
                product_data: { name: "Fund Donation" },
                unit_amount: amount * 100,
              },
              quantity: 1,
            },
          ],
          mode: "payment",
          success_url: `${process.env.CLIENT_URL}/funding?success=true`,
          cancel_url: `${process.env.CLIENT_URL}/funding?canceled=true`,
        });
        res.json({ url: session.url });
      } catch (error) {
        console.error("Stripe Checkout Error:", error);
        res.status(500).json({ error: "Unable to create checkout session" });
      }
    });

    // ====== FUNDING ROUTES ======
    // Get paginated funding records
    app.get("/api/funds", async (req, res) => {
      try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const total = await fundingCollection.countDocuments();
        const funds = await fundingCollection
          .find()
          .sort({ date: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.status(200).json({
          data: funds,
          pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit),
          },
        });
      } catch (error) {
        console.error("GET /api/funds error:", error);
        res.status(500).json({ message: "Failed to fetch funding records" });
      }
    });

    // Get funding statistics
    app.get("/api/funds/stats", async (req, res) => {
      try {
        const totalAgg = await fundingCollection
          .aggregate([
            {
              $group: {
                _id: null,
                totalFunds: { $sum: "$amount" },
                totalDonors: { $addToSet: "$email" },
              },
            },
          ])
          .toArray();
        const recent = await fundingCollection.findOne(
          {},
          { sort: { date: -1 } }
        );
        const stats = {
          totalFunds: totalAgg[0]?.totalFunds || 0,
          totalDonors: totalAgg[0]?.totalDonors.length || 0,
          recentAmount: recent?.amount || 0,
        };
        res.status(200).json(stats);
      } catch (err) {
        console.error("GET /api/funds/stats error:", err);
        res.status(500).json({ message: "Failed to fetch stats" });
      }
    });

    app.post("/api/funds", async (req, res) => {
      const { userEmail, userName, amount, currency, paymentIntentId } =
        req.body;

      if (!userEmail || !amount || !paymentIntentId) {
        return res
          .status(400)
          .json({ message: "Missing required donation data" });
      }

      try {
        const donation = {
          userEmail,
          userName,
          amount,
          currency: currency || "usd",
          paymentIntentId,
          status: "succeeded",
          createdAt: new Date(),
        };

        const result = await fundingCollection.insertOne(donation);

        res.status(201).json({
          message: "Donation saved successfully",
          donationId: result.insertedId,
        });
      } catch (err) {
        console.error("Error saving donation:", err);
        res.status(500).json({ message: "Failed to save donation" });
      }
    });

    // Create Stripe Payment Intent
    app.post("/api/payments/create-intent", async (req, res) => {
      const { amount, currency = "usd" } = req.body;
      if (!amount || amount < 1)
        return res.status(400).json({ message: "Invalid donation amount" });
      try {
        const paymentIntent = await stripe.paymentIntents.create({
          amount: Math.round(amount * 100),
          currency,
          automatic_payment_methods: { enabled: true },
        });
        res.json({ clientSecret: paymentIntent.client_secret });
      } catch (error) {
        console.error("Stripe intent error:", error);
        res.status(500).json({ message: "Failed to create payment intent" });
      }
    });
    // ====== SEARCH DONORS ENDPOINT ======
    app.get("/api/donors/search", async (req, res) => {
      try {
        const { bloodGroup, district, upazila } = req.query;

        // Build query
        const query = {
          role: "donor",
          status: "active",
          bloodGroup: bloodGroup,
        };

        if (district) query.district = district;
        if (upazila) query.upazila = upazila;

        // Search donors with projection
        const donors = await usersCollection
          .find(query, {
            projection: {
              _id: 1,
              name: 1,
              avatar: 1,
              bloodGroup: 1,
              district: 1,
              upazila: 1,
              lastDonationDate: 1,
              email: 1,
              phone: 1,
            },
          })
          .sort({ lastDonationDate: -1 })
          .toArray();

        res.status(200).json(donors);
      } catch (error) {
        console.error("Search error:", error);
        res.status(500).json({ error: "Failed to search donors" });
      }
    });

    // ====== CONTACT FORM ======
    app.post("/api/contact", async (req, res) => {
      const { name, email, message } = req.body;
      try {
        // confirmation to user
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: email,
          subject: "Thank you for contacting Donorly",
          html: `<h2>Hi ${name},</h2>
                 <p>We received your message:</p>
                 <blockquote>${message}</blockquote>
                 <p>We'll respond within 24h.</p><p>— Donorly Team</p>`,
        });
        // notify admin
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: process.env.ADMIN_EMAIL,
          subject: `New contact from ${name}`,
          text: `Name: ${name}\nEmail: ${email}\nMessage: ${message}`,
        });
        res.json({ success: true });
      } catch (err) {
        console.error("Email error:", err);
        res.status(500).json({ success: false, message: "Email failed" });
      }
    });

    // ==============================
    // GET all users (Admin only)
    // ==============================
    app.get("/api/users", verifyJWT, async (req, res) => {
      try {
        const email = req.decoded?.email;
        const user = await usersCollection.findOne({
          email: { $regex: new RegExp(`^${email}$`, "i") },
        });

        if (user?.role !== "admin") {
          return res.status(403).json({ message: "Forbidden: Admins only." });
        }

        const users = await usersCollection.find({}).toArray();
        res.status(200).json(users);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch users", error });
      }
    });

    // ==============================
    // GET logged-in user info
    // ==============================
    app.get("/api/user", verifyJWT, async (req, res) => {
      try {
        const email = req.decoded?.email;

        if (!email) {
          return res.status(401).json({
            success: false,
            message: "Unauthorized - Missing email in token",
          });
        }

        const user = await usersCollection.findOne({
          email: { $regex: new RegExp(`^${email}$`, "i") },
        });

        if (!user) {
          return res.status(404).json({
            success: false,
            message: "User not found",
          });
        }

        res.status(200).json({
          success: true,
          data: user,
        });
      } catch (error) {
        console.error("Error fetching user:", error);
        res.status(500).json({
          success: false,
          message: "Internal server error",
          error:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        });
      }
    });

    // ==============================
    // GET specific user by email (self or admin)
    // ==============================
    app.get("/api/users/:email", verifyJWT, async (req, res) => {
      const requestedEmail = req.params.email;
      const decodedEmail = req.decoded?.email;

      try {
        const requestingUser = await usersCollection.findOne({
          email: { $regex: new RegExp(`^${decodedEmail}$`, "i") },
        });

        if (!requestingUser) {
          return res.status(404).json({ message: "Requesting user not found" });
        }

        if (
          requestingUser.role !== "admin" &&
          decodedEmail !== requestedEmail
        ) {
          return res.status(403).json({
            message: "Access denied. You can only access your own data.",
          });
        }

        const targetUser = await usersCollection.findOne({
          email: { $regex: new RegExp(`^${requestedEmail}$`, "i") },
        });

        if (!targetUser) {
          return res.status(404).json({ message: "User not found" });
        }

        res.status(200).json(targetUser);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch user", error });
      }
    });

    // ==============================
    // CHECK admin status of current user
    // ==============================
    app.get("/api/users/check-admin", verifyJWT, async (req, res) => {
      try {
        const email = req.decoded?.email;

        if (!email) {
          return res.status(401).json({
            success: false,
            message: "Unauthorized - No email in token",
          });
        }

        const user = await usersCollection.findOne({
          email: { $regex: new RegExp(`^${email}$`, "i") },
          status: "active",
        });

        if (!user) {
          return res.status(404).json({
            success: false,
            message: "User not found or inactive",
            errorCode: "USER_NOT_FOUND",
          });
        }

        const isAdmin = user.role === "admin";

        res.status(200).json({
          success: true,
          isAdmin,
          user: {
            firebaseUid: user.firebaseUid,
            name: user.name,
            email: user.email,
            avatar: user.avatar,
            role: user.role,
            bloodGroup: user.bloodGroup,
            district: user.district,
            upazila: user.upazila,
            status: user.status,
          },
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Internal server error",
          errorCode: "SERVER_ERROR",
        });
      }
    });

    // ==============================
    // POST create user
    // ==============================
    app.post("/api/users", async (req, res) => {
      const {
        firebaseUid,
        name,
        email,
        avatar,
        bloodGroup,
        district,
        upazila,
        role = "donor",
        status = "active",
      } = req.body;

      if (!email || !name) {
        return res.status(400).json({
          success: false,
          message: "Name and email are required",
          field: !email ? "email" : "name",
        });
      }

      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({
          success: false,
          message: "Invalid email format",
          field: "email",
        });
      }

      try {
        const existingUser = await usersCollection.findOne({
          email: { $regex: new RegExp(`^${email}$`, "i") },
        });

        if (existingUser) {
          return res.status(200).json({
            success: true,
            message: "User already exists",
            data: {
              userId: existingUser._id,
              email: existingUser.email,
            },
          });
        }

        const newUser = {
          firebaseUid,
          name: name.trim(),
          email: email.toLowerCase().trim(),
          avatar: avatar || null,
          bloodGroup: bloodGroup || null,
          district: district || null,
          upazila: upazila || null,
          role,
          status,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await usersCollection.insertOne(newUser);

        res.status(201).json({
          success: true,
          message: "User created successfully",
          data: {
            userId: result.insertedId,
            email: newUser.email,
            name: newUser.name,
          },
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "User creation failed",
          error:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        });
      }
    });

    // ==============================
    // PATCH update user by email
    // ==============================
    app.patch("/api/users/:email", async (req, res) => {
      const { email } = req.params;
      const updates = req.body;

      try {
        const result = await usersCollection.updateOne(
          { email },
          { $set: updates }
        );

        if (result.modifiedCount === 0) {
          return res
            .status(404)
            .json({ message: "User not found or no changes made" });
        }

        res.status(200).json({ message: "User updated", success: true });
      } catch (error) {
        res.status(500).json({ message: "Update failed", error });
      }
    });

    // ==============================
    // DELETE user by MongoDB ID
    // ==============================
    app.delete("/api/users/:id", async (req, res) => {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      try {
        const result = await usersCollection.deleteOne({
          _id: new ObjectId(id),
        });

        if (result.deletedCount === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        res.status(200).json({ message: "User deleted", success: true });
      } catch (error) {
        res.status(500).json({ message: "Delete failed", error });
      }
    });

    // ==============================
    // PATCH update user status
    // ==============================
    app.patch("/api/users/status/:id", async (req, res) => {
      const { status } = req.body;
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      if (!status || !allowedStatuses.includes(status)) {
        return res.status(400).json({ message: "Invalid or missing status" });
      }

      try {
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status } }
        );

        if (result.modifiedCount === 0) {
          return res
            .status(404)
            .json({ message: "User not found or status unchanged" });
        }

        res.status(200).json({ message: "Status updated", success: true });
      } catch (error) {
        res.status(500).json({ message: "Status update failed", error });
      }
    });

    // ==============================
    // PATCH update user role
    // ==============================
    app.patch("/api/users/role/:id", async (req, res) => {
      const { role } = req.body;
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      if (!role || !allowedRoles.includes(role)) {
        return res.status(400).json({ message: "Invalid or missing role" });
      }

      try {
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { role } }
        );

        if (result.modifiedCount === 0) {
          return res
            .status(404)
            .json({ message: "User not found or role unchanged" });
        }

        res.status(200).json({ message: "Role updated", success: true });
      } catch (error) {
        res.status(500).json({ message: "Role update failed", error });
      }
    });

    // GET all donation requests with filters + pagination
    app.get("/api/donation-requests", async (req, res) => {
      try {
        const {
          page = 1,
          limit = 10,
          status,
          bloodGroup,
          district,
          upazila,
          sortBy = "createdAt",
          sortOrder = "desc",
          search,
          startDate,
          endDate,
        } = req.query;

        const pageNumber = parseInt(page);
        const limitNumber = parseInt(limit);
        const skip = (pageNumber - 1) * limitNumber;
        const sort = { [sortBy]: sortOrder === "asc" ? 1 : -1 };

        const filter = {};

        if (status) filter.status = status;
        if (bloodGroup) filter.bloodGroup = bloodGroup;
        if (district) filter.district = district;
        if (upazila) filter.upazila = upazila;

        if (startDate || endDate) {
          filter.createdAt = {};
          if (startDate) filter.createdAt.$gte = new Date(startDate);
          if (endDate) filter.createdAt.$lte = new Date(endDate);
        }

        if (search) {
          filter.$or = [
            { recipientName: { $regex: search, $options: "i" } },
            { hospital: { $regex: search, $options: "i" } },
            { address: { $regex: search, $options: "i" } },
            { message: { $regex: search, $options: "i" } },
          ];
        }

        const [requests, totalCount] = await Promise.all([
          donationRequestCollection
            .find(filter)
            .sort(sort)
            .skip(skip)
            .limit(limitNumber)
            .toArray(),
          donationRequestCollection.countDocuments(filter),
        ]);

        const totalPages = Math.ceil(totalCount / limitNumber);

        res.status(200).json({
          success: true,
          data: requests,
          pagination: {
            totalItems: totalCount,
            totalPages,
            currentPage: pageNumber,
            itemsPerPage: limitNumber,
            hasNext: pageNumber < totalPages,
            hasPrevious: pageNumber > 1,
          },
        });
      } catch (error) {
        console.error("Error fetching donation requests:", error);
        res
          .status(500)
          .json({ success: false, error: "Internal server error" });
      }
    });

    // GET recent 3 donation requests (sorted by date descending)
    app.get("/api/donation-requests/recent", async (req, res) => {
      try {
        const recentRequests = await donationRequestCollection
          .find()
          .sort({ date: -1 })
          .limit(3)
          .toArray();
        res.json({ success: true, data: recentRequests });
      } catch (error) {
        console.error("Error fetching recent requests:", error);
        res
          .status(500)
          .json({ success: false, error: "Internal server error" });
      }
    });

    // GET single donation request by ID
    app.get("/api/donation-requests/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const request = await donationRequestCollection.findOne(query);
        if (!request) {
          return res.status(404).json({ success: false, error: "Not found" });
        }
        res.json(request);
      } catch (error) {
        console.error("Error fetching request:", error);
        res
          .status(500)
          .json({ success: false, error: "Internal server error" });
      }
    });

    // POST new donation request
    app.post("/api/donation-requests", async (req, res) => {
      try {
        const {
          recipientName,
          district,
          upazila,
          hospital,
          address,
          bloodGroup,
          date,
          time,
          message,
          requesterName,
          requesterEmail,
        } = req.body;

        const requiredFields = [
          recipientName,
          district,
          upazila,
          hospital,
          address,
          bloodGroup,
          date,
          time,
          message,
        ];

        if (requiredFields.some((f) => !f)) {
          return res
            .status(400)
            .json({ success: false, error: "Missing required fields" });
        }

        const newRequest = {
          recipientName,
          district,
          upazila,
          hospital,
          address,
          bloodGroup,
          date,
          time,
          message,
          requesterName,
          requesterEmail,
          status: "pending",
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await donationRequestCollection.insertOne(newRequest);
        res.status(201).json({
          success: true,
          requestId: result.insertedId,
          message: "Request created successfully",
        });
      } catch (error) {
        console.error("Error creating donation request:", error);
        res
          .status(500)
          .json({ success: false, error: "Internal server error" });
      }
    });

    app.patch("/api/donation-requests/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const {
          recipientName,
          district,
          upazila,
          hospital,
          address,
          bloodGroup,
          date,
          time,
          message,
        } = req.body;

        // Basic validation
        if (!ObjectId.isValid(id)) {
          return res
            .status(400)
            .json({ success: false, error: "Invalid ID format" });
        }

        const updateData = {
          recipientName,
          district,
          upazila,
          hospital,
          address,
          bloodGroup,
          date,
          time,
          message,
          updatedAt: new Date(),
          status: "pending", // Reset status when edited
        };

        const result = await donationRequestCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData }
        );

        if (result.matchedCount === 0) {
          return res
            .status(404)
            .json({ success: false, error: "Request not found" });
        }

        res.json({
          success: result.modifiedCount === 1,
          message:
            result.modifiedCount === 1
              ? "Request updated successfully"
              : "No changes made",
          data: updateData,
        });
      } catch (error) {
        console.error("Error updating donation request:", error);
        res
          .status(500)
          .json({ success: false, error: "Internal server error" });
      }
    });

    // PATCH donation status
    app.patch("/api/donation-requests/status/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const { status } = req.body;
        const validStatuses = ["pending", "inprogress", "done", "canceled"];

        if (!validStatuses.includes(status)) {
          return res
            .status(400)
            .json({ success: false, error: "Invalid status" });
        }

        const result = await donationRequestCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status, updatedAt: new Date() } }
        );

        res.json({
          success: result.modifiedCount === 1,
          message:
            result.modifiedCount === 1
              ? "Status updated successfully"
              : "No changes made",
        });
      } catch (error) {
        console.error("Error updating donation status:", error);
        res
          .status(500)
          .json({ success: false, error: "Internal server error" });
      }
    });

    app.delete(
      "/api/donation-requests/:id",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        const result = await donationRequestCollection.deleteOne({
          _id: new ObjectId(req.params.id),
        });
        res.json({ success: result.deletedCount === 1 });
      }
    );

    // Get all blogs with filtering and pagination
    app.get("/api/blogs", async (req, res) => {
      try {
        const {
          status = "published",
          search,
          authorId,
          page = 1,
          limit = 10,
          sort = "-createdAt",
        } = req.query;

        const filter = { status };

        // Author filter
        if (authorId) {
          filter.authorId = new ObjectId(authorId);
        }

        // Search filter
        if (search) {
          filter.$or = [
            { title: { $regex: search, $options: "i" } },
            { content: { $regex: search, $options: "i" } },
            { author: { $regex: search, $options: "i" } },
          ];
        }

        // Sort option
        const sortOption = {};
        if (sort.startsWith("-")) {
          sortOption[sort.substring(1)] = -1;
        } else {
          sortOption[sort] = 1;
        }

        // Pagination
        const skip = (page - 1) * limit;
        const totalBlogs = await blogsCollection.countDocuments(filter);
        const totalPages = Math.ceil(totalBlogs / limit);

        // Projection
        const projection = {
          title: 1,
          author: 1,
          thumbnail: 1,
          status: 1,
          views: 1,
          createdAt: 1,
          slug: 1,
          _id: 1,
        };

        const blogs = await blogsCollection
          .find(filter)
          .sort(sortOption)
          .skip(skip)
          .limit(parseInt(limit))
          .project(projection)
          .toArray();

        res.json({
          success: true,
          count: blogs.length,
          total: totalBlogs,
          page: parseInt(page),
          totalPages,
          data: blogs,
        });
      } catch (error) {
        console.error("Error fetching blogs:", error);
        res.status(500).json({
          success: false,
          message: "Server error fetching blogs",
          error: error.message,
        });
      }
    });

    // Get single blog
    app.get("/api/blogs/:id", async (req, res) => {
      try {
        if (!ObjectId.isValid(req.params.id)) {
          return res.status(400).json({
            success: false,
            message: "Invalid blog ID",
          });
        }

        const blog = await blogsCollection.findOne({
          _id: new ObjectId(req.params.id),
        });

        if (!blog) {
          return res.status(404).json({
            success: false,
            message: "Blog not found",
          });
        }

        res.json({
          success: true,
          data: blog,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Server error fetching blog",
          error: error.message,
        });
      }
    });

    // Create new blog
    app.post("/api/blogs", async (req, res) => {
      try {
        const { title, content, thumbnail, authorId } = req.body;

        if (!title || !content || !thumbnail || !authorId) {
          return res.status(400).json({
            success: false,
            message: "Title, content, thumbnail and authorId are required",
          });
        }

        // Get author info
        const author = await usersCollection.findOne({
          _id: new ObjectId(authorId),
        });

        if (!author) {
          return res.status(400).json({
            success: false,
            message: "Author not found",
          });
        }

        const slug = title
          .toLowerCase()
          .replace(/[^\w\s]/gi, "")
          .replace(/\s+/g, "-");

        const newBlog = {
          title,
          content,
          thumbnail,
          author: author.name,
          authorId: new ObjectId(authorId),
          authorEmail: author.email,
          status: "draft",
          views: 0,
          comments: [],
          likes: [],
          createdAt: new Date(),
          updatedAt: new Date(),
          slug,
        };

        const result = await blogsCollection.insertOne(newBlog);

        res.status(201).json({
          success: true,
          data: {
            ...newBlog,
            _id: result.insertedId,
          },
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Server error creating blog",
          error: error.message,
        });
      }
    });

    // Update blog
    app.put("/api/blogs/:id", async (req, res) => {
      try {
        if (!ObjectId.isValid(req.params.id)) {
          return res.status(400).json({
            success: false,
            message: "Invalid blog ID",
          });
        }

        const { title, content, thumbnail } = req.body;
        const blogId = new ObjectId(req.params.id);

        const blog = await blogsCollection.findOne({ _id: blogId });

        if (!blog) {
          return res.status(404).json({
            success: false,
            message: "Blog not found",
          });
        }

        const update = {
          $set: {
            title: title || blog.title,
            content: content || blog.content,
            thumbnail: thumbnail || blog.thumbnail,
            updatedAt: new Date(),
          },
        };

        const result = await blogsCollection.updateOne({ _id: blogId }, update);

        if (result.modifiedCount === 0) {
          return res.status(400).json({
            success: false,
            message: "No changes made to blog",
          });
        }

        const updatedBlog = await blogsCollection.findOne({ _id: blogId });

        res.json({
          success: true,
          data: updatedBlog,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Server error updating blog",
          error: error.message,
        });
      }
    });

    // Update blog status
    app.patch("/api/blogs/:id/status", async (req, res) => {
      try {
        if (!ObjectId.isValid(req.params.id)) {
          return res.status(400).json({
            success: false,
            message: "Invalid blog ID",
          });
        }

        const { status } = req.body;
        const validStatuses = ["draft", "published", "archived"];

        if (!validStatuses.includes(status)) {
          return res.status(400).json({
            success: false,
            message: "Invalid status value",
          });
        }

        const result = await blogsCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { status, updatedAt: new Date() } }
        );

        if (result.modifiedCount === 0) {
          return res.status(404).json({
            success: false,
            message: "Blog not found or no changes made",
          });
        }

        const updatedBlog = await blogsCollection.findOne({
          _id: new ObjectId(req.params.id),
        });

        res.json({
          success: true,
          data: updatedBlog,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Server error updating blog status",
          error: error.message,
        });
      }
    });

    // Track blog view
    app.patch("/api/blogs/:id/views", async (req, res) => {
      try {
        if (!ObjectId.isValid(req.params.id)) {
          return res.status(400).json({
            success: false,
            message: "Invalid blog ID",
          });
        }

        const result = await blogsCollection.findOneAndUpdate(
          { _id: new ObjectId(req.params.id) },
          {
            $inc: { views: 1 },
            $push: {
              viewDetails: {
                viewedAt: new Date(),
                userAgent: req.headers["user-agent"],
                ipAddress: req.ip,
                referrer: req.headers.referer,
              },
            },
          },
          {
            returnDocument: "after",
            projection: { views: 1, title: 1 },
          }
        );

        if (!result.value) {
          return res.status(404).json({
            success: false,
            message: "Blog not found",
          });
        }

        res.json({
          success: true,
          views: result.value.views,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Failed to track view",
          error: error.message,
        });
      }
    });

    // Delete blog
    app.delete("/api/blogs/:id", async (req, res) => {
      try {
        if (!ObjectId.isValid(req.params.id)) {
          return res.status(400).json({
            success: false,
            message: "Invalid blog ID",
          });
        }

        const result = await blogsCollection.deleteOne({
          _id: new ObjectId(req.params.id),
        });

        if (result.deletedCount === 0) {
          return res.status(404).json({
            success: false,
            message: "Blog not found",
          });
        }

        res.json({
          success: true,
          message: "Blog deleted successfully",
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Server error deleting blog",
          error: error.message,
        });
      }
    });

    // Add comment to blog
    app.post("/api/blogs/:id/comments", async (req, res) => {
      try {
        if (!ObjectId.isValid(req.params.id)) {
          return res.status(400).json({
            success: false,
            message: "Invalid blog ID",
          });
        }

        const { content, authorId } = req.body;

        if (!content || !authorId) {
          return res.status(400).json({
            success: false,
            message: "Content and authorId are required",
          });
        }

        // Get author info
        const author = await usersCollection.findOne({
          _id: new ObjectId(authorId),
        });

        if (!author) {
          return res.status(400).json({
            success: false,
            message: "Author not found",
          });
        }

        const newComment = {
          _id: new ObjectId(),
          content,
          author: {
            id: new ObjectId(authorId),
            name: author.name,
            avatar: author.avatar,
          },
          likes: [],
          createdAt: new Date(),
        };

        const result = await blogsCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $push: { comments: newComment } }
        );

        if (result.modifiedCount === 0) {
          return res.status(404).json({
            success: false,
            message: "Blog not found",
          });
        }

        res.status(201).json({
          success: true,
          data: newComment,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Failed to add comment",
          error: error.message,
        });
      }
    });

    // Like/unlike comment
    app.patch("/api/comments/:id/like", async (req, res) => {
      try {
        if (
          !ObjectId.isValid(req.params.id) ||
          !ObjectId.isValid(req.body.userId)
        ) {
          return res.status(400).json({
            success: false,
            message: "Invalid ID format",
          });
        }

        const commentId = new ObjectId(req.params.id);
        const userId = new ObjectId(req.body.userId);

        // Find the blog containing the comment
        const blog = await blogsCollection.findOne({
          "comments._id": commentId,
        });

        if (!blog) {
          return res.status(404).json({
            success: false,
            message: "Comment not found",
          });
        }

        // Find the comment and update likes
        const comment = blog.comments.find((c) => c._id.equals(commentId));
        const likeIndex = comment.likes.findIndex((id) => id.equals(userId));

        let update;
        let isLiked;

        if (likeIndex === -1) {
          // Add like
          update = { $push: { "comments.$[elem].likes": userId } };
          isLiked = true;
        } else {
          // Remove like
          update = { $pull: { "comments.$[elem].likes": userId } };
          isLiked = false;
        }

        const result = await blogsCollection.updateOne(
          { _id: blog._id, "comments._id": commentId },
          update,
          { arrayFilters: [{ "elem._id": commentId }] }
        );

        if (result.modifiedCount === 0) {
          return res.status(400).json({
            success: false,
            message: "Failed to update like status",
          });
        }

        // Get updated likes count
        const updatedBlog = await blogsCollection.findOne({ _id: blog._id });
        const updatedComment = updatedBlog.comments.find((c) =>
          c._id.equals(commentId)
        );

        res.json({
          success: true,
          likes: updatedComment.likes,
          isLiked,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Failed to update comment like",
          error: error.message,
        });
      }
    });

    console.log("✅ MongoDB Connected");
  } catch (err) {
    console.error("❌ DB connection error:", err);
  }
}
run();

// ====== Default Route ======
app.get("/", (req, res) => {
  res.send("🩸 Blood Donation App Server is Running");
});

// ====== Start Server ======
app.listen(port, () => {
  console.log(`🚀 Server listening on port ${port}`);
});
module.exports = app;
