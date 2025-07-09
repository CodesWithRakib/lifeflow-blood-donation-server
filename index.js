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
  origin: process.env.CLIENT_URL,
  credentials: true,
  optionSuccessStatus: 200,
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
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ success: false, message: "Forbidden" });
    }
    req.userEmail = decoded.email;
    next();
  });
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
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        })
        .json({ message: "JWT set" });
    });

    app.post("/logout", (req, res) => {
      res.clearCookie("jwt").json({ message: "Logged out" });
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

    const { ObjectId } = require("mongodb");

    // GET all users
    app.get("/api/users", async (req, res) => {
      try {
        const users = await usersCollection.find().toArray();
        res.status(200).json(users);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch users", error });
      }
    });

    // GET single user by email
    app.get("/api/users/:email", async (req, res) => {
      const { email } = req.params;
      try {
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }
        res.status(200).json(user);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch user", error });
      }
    });

    // POST create user (register or sync from Firebase)
    app.post("/api/users", async (req, res) => {
      const user = req.body;

      if (!user?.email || !user?.name) {
        return res.status(400).json({ message: "Name and Email are required" });
      }

      try {
        const existingUser = await usersCollection.findOne({
          email: user.email,
        });

        if (existingUser) {
          return res
            .status(200)
            .json({ message: "User already exists", user: existingUser });
        }

        const result = await usersCollection.insertOne(user);
        res.status(201).json({
          message: "User created",
          success: true,
          userId: result.insertedId,
        });
      } catch (error) {
        res.status(500).json({ message: "User creation failed", error });
      }
    });

    // PATCH update user by email
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

    // DELETE user by MongoDB _id
    app.delete("/api/users/:id", async (req, res) => {
      try {
        const result = await usersCollection.deleteOne({
          _id: new ObjectId(req.params.id),
        });
        if (result.deletedCount === 0) {
          return res.status(404).json({ message: "User not found" });
        }
        res.status(200).json({ message: "User deleted", success: true });
      } catch (error) {
        res.status(500).json({ message: "Delete failed", error });
      }
    });

    // PATCH update user status (e.g., active/inactive)
    app.patch("/api/users/status/:id", async (req, res) => {
      const { status } = req.body;
      if (!status) {
        return res.status(400).json({ message: "Status is required" });
      }

      try {
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
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

    app.patch("/api/users/role/:id", async (req, res) => {
      const { role } = req.body;
      if (!role) {
        return res.status(400).json({ message: "Role is required" });
      }

      try {
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
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

    // ====== ADMIN: Donation Request Management ======
    app.get("/api/donation-requests", async (req, res) => {
      try {
        // Extract query parameters with default values
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

        // Validate pagination parameters
        const pageNumber = parseInt(page);
        const limitNumber = parseInt(limit);

        if (isNaN(pageNumber) || pageNumber < 1) {
          return res.status(400).json({
            success: false,
            error: "Invalid page number (must be positive integer)",
          });
        }

        if (isNaN(limitNumber) || limitNumber < 1 || limitNumber > 100) {
          return res.status(400).json({
            success: false,
            error: "Invalid limit (must be between 1 and 100)",
          });
        }

        // Build filter object based on query parameters
        const filter = {};

        // Status filter
        if (status) {
          const validStatuses = [
            "pending",
            "approved",
            "fulfilled",
            "rejected",
          ];
          if (validStatuses.includes(status)) {
            filter.status = status;
          } else {
            return res.status(400).json({
              success: false,
              error: "Invalid status value",
              validStatuses,
            });
          }
        }

        // Blood group filter
        if (bloodGroup) {
          const validBloodGroups = [
            "A+",
            "A-",
            "B+",
            "B-",
            "AB+",
            "AB-",
            "O+",
            "O-",
          ];
          if (validBloodGroups.includes(bloodGroup)) {
            filter.bloodGroup = bloodGroup;
          } else {
            return res.status(400).json({
              success: false,
              error: "Invalid blood group",
              validBloodGroups,
            });
          }
        }

        // Location filters
        if (district) filter.district = district;
        if (upazila) filter.upazila = upazila;

        // Date range filter
        if (startDate || endDate) {
          filter.createdAt = {};
          if (startDate) {
            filter.createdAt.$gte = new Date(startDate);
          }
          if (endDate) {
            filter.createdAt.$lte = new Date(endDate);
          }
        }

        // Text search (case-insensitive)
        if (search) {
          filter.$or = [
            { recipientName: { $regex: search, $options: "i" } },
            { hospital: { $regex: search, $options: "i" } },
            { address: { $regex: search, $options: "i" } },
            { message: { $regex: search, $options: "i" } },
          ];
        }

        // Validate sort parameters
        const validSortFields = [
          "createdAt",
          "date",
          "recipientName",
          "status",
        ];
        const sortDirection = sortOrder === "asc" ? 1 : -1;

        if (!validSortFields.includes(sortBy)) {
          return res.status(400).json({
            success: false,
            error: "Invalid sort field",
            validSortFields,
          });
        }

        // Execute query with pagination
        const skip = (pageNumber - 1) * limitNumber;
        const sort = { [sortBy]: sortDirection };

        const [requests, totalCount] = await Promise.all([
          donationRequestCollection
            .find(filter)
            .sort(sort)
            .skip(skip)
            .limit(limitNumber)
            .toArray(),
          donationRequestCollection.countDocuments(filter),
        ]);

        // Calculate pagination metadata
        const totalPages = Math.ceil(totalCount / limitNumber);
        const hasNext = pageNumber < totalPages;
        const hasPrevious = pageNumber > 1;

        // Return response with metadata
        return res.status(200).json({
          success: true,
          data: requests,
          pagination: {
            totalItems: totalCount,
            totalPages,
            currentPage: pageNumber,
            itemsPerPage: limitNumber,
            hasNext,
            hasPrevious,
          },
          filters: {
            applied: Object.keys(filter).length > 0 ? filter : "none",
            sort: {
              by: sortBy,
              order: sortOrder,
            },
          },
        });
      } catch (error) {
        console.error("Error fetching donation requests:", error);
        return res.status(500).json({
          success: false,
          error: "Internal server error",
          message: "Failed to fetch donation requests",
        });
      }
    });

    app.get("/api/donation-requests/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const request = await donationRequestCollection.findOne(query);
      res.json(request);
    });

    app.post("/api/donation-requests", async (req, res) => {
      try {
        // Validate request body
        const requiredFields = [
          "recipientName",
          "district",
          "upazila",
          "hospital",
          "address",
          "bloodGroup",
          "date",
          "time",
          "message",
        ];

        const missingFields = requiredFields.filter(
          (field) => !req.body[field]
        );
        if (missingFields.length > 0) {
          return res.status(400).json({
            success: false,
            error: "Missing required fields",
            missingFields,
          });
        }

        // Validate blood group
        const validBloodGroups = [
          "A+",
          "A-",
          "B+",
          "B-",
          "AB+",
          "AB-",
          "O+",
          "O-",
        ];
        if (!validBloodGroups.includes(req.body.bloodGroup)) {
          return res.status(400).json({
            success: false,
            error: "Invalid blood group",
          });
        }

        // Validate date format (simple check)
        if (!/^\d{4}-\d{2}-\d{2}$/.test(req.body.date)) {
          return res.status(400).json({
            success: false,
            error: "Invalid date format (YYYY-MM-DD required)",
          });
        }

        // Create request object with additional metadata
        const donationRequest = {
          ...req.body,
          requesterName: req.body.requesterName,
          requesterEmail: req.body.requesterEmail,
          status: "pending",
          createdAt: new Date(),
          updatedAt: new Date(),
          ipAddress: req.ip,
          userAgent: req.headers["user-agent"],
        };

        // Insert into database
        const result = await donationRequestCollection.insertOne(
          donationRequest
        );

        if (!result.acknowledged) {
          throw new Error("Database insertion not acknowledged");
        }

        // Log successful creation (in a real app, use a proper logger)
        console.log(
          `New donation request created with ID: ${result.insertedId}`
        );

        // Return success response
        return res.status(201).json({
          success: true,
          requestId: result.insertedId,
          message: "Donation request created successfully",
        });
      } catch (error) {
        console.error("Error creating donation request:", error);

        return res.status(500).json({
          success: false,
          error: "Internal server error",
          message: "Failed to create donation request",
        });
      }
    });
    app.patch("/api/donation-requests/status/:id", async (req, res) => {
      const { status } = req.body;
      const result = await donationRequestCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { status } }
      );
      res.json({ success: result.modifiedCount === 1 });
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

    // blogs route

    // Get all blogs (Public) with enhanced filtering
    app.get("/api/blogs", async (req, res) => {
      try {
        const {
          status,
          search,
          authorId,
          page = 1,
          limit = 10,
          sort = "-createdAt", // Default: newest first
        } = req.query;

        const filter = {};

        // Status filter (only show published blogs to public by default)
        filter.status = status || "published";

        // Author filter
        if (authorId) {
          filter.authorId = authorId;
        }

        // Search filter (title, content, or author name)
        if (search) {
          filter.$or = [
            { title: { $regex: search, $options: "i" } },
            { content: { $regex: search, $options: "i" } },
            { author: { $regex: search, $options: "i" } },
          ];
        }

        // Parse sort parameter
        const sortOption = {};
        if (sort.startsWith("-")) {
          sortOption[sort.substring(1)] = -1; // Descending
        } else {
          sortOption[sort] = 1; // Ascending
        }

        // Pagination calculations
        const skip = (page - 1) * limit;
        const totalBlogs = await blogsCollection.countDocuments(filter);
        const totalPages = Math.ceil(totalBlogs / limit);

        // Get paginated blogs with selected fields
        const blogs = await blogsCollection
          .find(filter)
          .sort(sortOption)
          .skip(skip)
          .limit(parseInt(limit))
          .project({
            title: 1,
            author: 1,
            authorEmail: 1,
            thumbnail: 1,
            content: 1,
            status: 1,
            views: 1,
            slug: 1,
            createdAt: 1,
            updatedAt: 1,
            _id: 1,
          })
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

    // Get single blog (Public)
    app.get("/api/blogs/:id", async (req, res) => {
      try {
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

    // Create a new blog (Admin only)
    app.post("/api/blogs", async (req, res) => {
      try {
        const { title, content, thumbnail } = req.body;

        if (!title || !content || !thumbnail) {
          return res.status(400).json({
            success: false,
            message: "Title, content and thumbnail are required",
          });
        }

        const blog = {
          ...req.body,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await db.collection("blogs").insertOne(blog);

        res.status(201).json({
          success: true,
          data: { ...blog, _id: result.insertedId },
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Server error creating blog",
          error: error.message,
        });
      }
    });

    // Update blog (Admin or Author)
    app.put("/api/blogs/:id", async (req, res) => {
      try {
        const { title, content, thumbnail } = req.body;
        const blogId = new ObjectId(req.params.id);

        const blog = await blogsCollection.findOne({ _id: blogId });

        if (!blog) {
          return res.status(404).json({
            success: false,
            message: "Blog not found",
          });
        }

        // Check if user is admin or author
        if (!blog.authorId.equals(req.user.id) && req.user.role !== "admin") {
          return res.status(403).json({
            success: false,
            message: "Not authorized to update this blog",
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

    // Update blog status (Admin only)
    app.patch("/api/blogs/:id/status", async (req, res) => {
      try {
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

    // Increment blog views and track view details
    app.patch("/api/blogs/:id/views", async (req, res) => {
      try {
        const { id } = req.params;
        const userAgent = req.headers["user-agent"];
        const ipAddress = req.ip || req.connection.remoteAddress;
        const referrer = req.headers.referer || req.headers.referrer;

        // Validate blog ID
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({
            success: false,
            message: "Invalid blog ID format",
          });
        }

        // Update the blog's view count and add view details
        const result = await blogsCollection.findOneAndUpdate(
          { _id: new ObjectId(id) },
          {
            $inc: { views: 1 },
            $push: {
              viewDetails: {
                viewedAt: new Date(),
                userAgent,
                ipAddress,
                referrer,
              },
            },
          },
          {
            returnDocument: "after",
            projection: {
              views: 1,
              title: 1,
            },
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
          message: "View counted successfully",
          newViewCount: result.value.views,
          blogTitle: result.value.title,
        });
      } catch (error) {
        console.error("Error tracking view:", error);
        res.status(500).json({
          success: false,
          message: "Failed to track view",
          error: error.message,
        });
      }
    });

    // Delete blog (Admin only)
    app.delete("/api/blogs/:id", async (req, res) => {
      try {
        const result = await db.collection("blogs").deleteOne({
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
