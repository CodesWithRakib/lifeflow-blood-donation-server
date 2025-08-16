require("dotenv").config();
const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
const nodemailer = require("nodemailer");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const PDFDocument = require("pdfkit");
const fs = require("fs");
const path = require("path");

const app = express();

// ====== Middleware Setup ======
const corsOptions = {
  origin: [
    "http://localhost:5173",
    "https://blood-donation-full-stack.web.app",
  ], // you can allow multiple origins if needed
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
    req.userEmail = decoded.email;
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
  emergencyRequestCollection,
  blogsCollection,
  fundingCollection;

const allowedStatuses = ["active", "blocked", "inactive"];
const allowedRoles = ["donor", "volunteer", "admin"];

// Helper functions
function getBrowser(userAgent) {
  // Implement browser detection logic
  if (/edg/i.test(userAgent)) return "Edge";
  if (/chrome/i.test(userAgent)) return "Chrome";
  if (/firefox/i.test(userAgent)) return "Firefox";
  if (/safari/i.test(userAgent)) return "Safari";
  return "Other";
}

function getOS(userAgent) {
  // Implement OS detection logic
  if (/windows/i.test(userAgent)) return "Windows";
  if (/macintosh/i.test(userAgent)) return "MacOS";
  if (/linux/i.test(userAgent)) return "Linux";
  if (/android/i.test(userAgent)) return "Android";
  if (/iphone|ipad|ipod/i.test(userAgent)) return "iOS";
  return "Unknown";
}

async function run() {
  try {
    const db = client.db("bloodDonationApp");
    usersCollection = db.collection("users");
    donationRequestCollection = db.collection("donationRequest");
    emergencyRequestCollection = db.collection("emergencyRequests");
    fundingCollection = db.collection("funds");
    blogsCollection = db.collection("blogs");

    // ====== AUTH ROUTES ======
    app.post("/api/jwt", (req, res) => {
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

    app.post("/api/logout", (req, res) => {
      res
        .clearCookie("jwt", {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production", // ✅ HTTPS-only in prod
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict", // ✅ CORS-safe
        })
        .json({ message: "Logout successful" });
    });

    // ====== FUNDING ROUTES ======
    app.get("/api/funds", verifyJWT, async (req, res) => {
      // Validate and parse pagination parameters
      const page = Math.max(1, parseInt(req.query.page)) || 1;
      const limit = Math.min(100, Math.max(1, parseInt(req.query.limit))) || 10;

      try {
        const skip = (page - 1) * limit;

        // Execute all queries in parallel for maximum performance
        const [totalRecords, records, totalStats, recentDonation] =
          await Promise.all([
            fundingCollection.countDocuments(),
            fundingCollection
              .find()
              .sort({ createdAt: -1 })
              .skip(skip)
              .limit(limit)
              .toArray(),
            fundingCollection
              .aggregate([
                {
                  $group: {
                    _id: null,
                    totalFunds: { $sum: "$amount" },
                    uniqueDonors: { $addToSet: "$userEmail" },
                  },
                },
              ])
              .toArray(),
            fundingCollection.findOne(
              {},
              {
                sort: { createdAt: -1 },
                projection: { amount: 1 },
              }
            ),
          ]);

        // Extract stats from aggregation results
        const statsResult = totalStats[0] || {};

        // Prepare complete response
        const response = {
          success: true,
          data: records,
          stats: {
            totalFunds: statsResult.totalFunds || 0,
            totalDonors: statsResult.uniqueDonors?.length || 0,
            recentAmount: recentDonation?.amount || 0,
          },
          pagination: {
            currentPage: page,
            itemsPerPage: limit,
            totalItems: totalRecords,
            totalPages: Math.ceil(totalRecords / limit),
            hasNextPage: page * limit < totalRecords,
          },
        };

        res.status(200).json(response);
      } catch (error) {
        console.error("[GET /api/funds] Error:", error);

        res.status(500).json({
          success: false,
          message: "Failed to retrieve funding records",
          error:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        });
      }
    });

    app.get("/api/funds/stats", verifyJWT, async (req, res) => {
      try {
        const now = new Date();
        const oneWeekAgo = new Date(now);
        oneWeekAgo.setDate(now.getDate() - 7);

        const oneMonthAgo = new Date(now);
        oneMonthAgo.setMonth(now.getMonth() - 1);

        const oneYearAgo = new Date(now);
        oneYearAgo.setFullYear(now.getFullYear() - 1);

        // Fetch all stats in parallel
        const [
          totalStats,
          recentStats,
          weeklyStats,
          monthlyStats,
          yearlyStats,
        ] = await Promise.all([
          fundingCollection
            .aggregate([
              {
                $group: {
                  _id: null,
                  totalFunds: { $sum: "$amount" },
                  uniqueDonors: { $addToSet: "$userEmail" },
                  count: { $sum: 1 },
                  avgAmount: { $avg: "$amount" },
                },
              },
            ])
            .toArray(),

          fundingCollection.findOne(
            {},
            {
              sort: { createdAt: -1 },
              projection: {
                amount: 1,
                userEmail: 1,
                userName: 1,
                createdAt: 1,
              },
            }
          ),

          // Weekly stats (last 7 days)
          fundingCollection
            .aggregate([
              {
                $match: {
                  createdAt: { $gte: oneWeekAgo },
                },
              },
              {
                $group: {
                  _id: {
                    $dateToString: { format: "%Y-%m-%d", date: "$createdAt" },
                  },
                  total: { $sum: "$amount" },
                  count: { $sum: 1 },
                  donors: { $addToSet: "$userEmail" },
                },
              },
              { $sort: { _id: 1 } },
            ])
            .toArray(),

          // Monthly stats (last 30 days)
          fundingCollection
            .aggregate([
              {
                $match: {
                  createdAt: { $gte: oneMonthAgo },
                },
              },
              {
                $group: {
                  _id: {
                    $dateToString: { format: "%Y-%m-%d", date: "$createdAt" },
                  },
                  total: { $sum: "$amount" },
                  count: { $sum: 1 },
                  donors: { $addToSet: "$userEmail" },
                },
              },
              { $sort: { _id: 1 } },
            ])
            .toArray(),

          // Yearly stats (last 12 months)
          fundingCollection
            .aggregate([
              {
                $match: {
                  createdAt: { $gte: oneYearAgo },
                },
              },
              {
                $group: {
                  _id: {
                    $dateToString: { format: "%Y-%m", date: "$createdAt" },
                  },
                  total: { $sum: "$amount" },
                  count: { $sum: 1 },
                  donors: { $addToSet: "$userEmail" },
                },
              },
              { $sort: { _id: 1 } },
            ])
            .toArray(),
        ]);

        const stats = totalStats[0] || {};

        res.status(200).json({
          success: true,
          data: {
            // Summary stats
            totalFunds: stats.totalFunds || 0,
            totalDonors: stats.uniqueDonors?.length || 0,
            totalDonations: stats.count || 0,
            avgDonation: stats.avgAmount ? stats.avgAmount.toFixed(2) : 0,

            // Recent activity
            recentDonation: {
              amount: recentStats?.amount || 0,
              donorEmail: recentStats?.userEmail || null,
              donorName: recentStats?.userName || null,
              date: recentStats?.createdAt || null,
            },

            // Time period stats
            weekly: {
              total: weeklyStats.reduce((sum, item) => sum + item.total, 0),
              donors: new Set(weeklyStats.flatMap((item) => item.donors)).size,
              donations: weeklyStats.reduce((sum, item) => sum + item.count, 0),
              trends: weeklyStats.map((entry) => ({
                date: entry._id,
                total: entry.total,
              })),
            },

            monthly: {
              total: monthlyStats.reduce((sum, item) => sum + item.total, 0),
              donors: new Set(monthlyStats.flatMap((item) => item.donors)).size,
              donations: monthlyStats.reduce(
                (sum, item) => sum + item.count,
                0
              ),
              trends: monthlyStats.map((entry) => ({
                date: entry._id,
                total: entry.total,
              })),
            },

            yearly: {
              total: yearlyStats.reduce((sum, item) => sum + item.total, 0),
              donors: new Set(yearlyStats.flatMap((item) => item.donors)).size,
              donations: yearlyStats.reduce((sum, item) => sum + item.count, 0),
              trends: yearlyStats.map((entry) => ({
                date: entry._id,
                total: entry.total,
              })),
            },

            primaryCurrency: "usd",
          },
        });
      } catch (error) {
        console.error("[GET /api/funds/stats] Error:", error);
        res.status(500).json({
          success: false,
          message: "Failed to fetch funding statistics",
          error:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        });
      }
    });

    // Add this endpoint to your existing routes
    app.get("/api/funds/report", verifyJWT, async (req, res) => {
      try {
        // Fetch data
        const [stats, recentDonations] = await Promise.all([
          fundingCollection
            .aggregate([
              {
                $group: {
                  _id: null,
                  totalFunds: { $sum: "$amount" },
                  uniqueDonors: { $addToSet: "$userEmail" },
                  count: { $sum: 1 },
                  avgAmount: { $avg: "$amount" },
                },
              },
            ])
            .toArray(),
          fundingCollection.find().sort({ createdAt: -1 }).limit(10).toArray(),
        ]);

        const reportStats = stats[0] || {};
        const now = new Date();

        // PDF Setup
        const doc = new PDFDocument({
          margin: 50,
          size: "A4",
          info: {
            Title: "LifeFlow Donation Report",
            Author: "LifeFlow System",
            CreationDate: now,
          },
        });

        // Response headers
        res.setHeader("Content-Type", "application/pdf");
        res.setHeader(
          "Content-Disposition",
          `attachment; filename=donation-report-${
            now.toISOString().split("T")[0]
          }.pdf`
        );

        doc.pipe(res);

        // Styles
        const primaryColor = "#e74c3c"; // Blood red
        const secondaryColor = "#34495e"; // Dark blue-gray
        const lightGray = "#f5f5f5";

        // Header
        doc
          .fillColor(primaryColor)
          .fontSize(24)
          .font("Helvetica-Bold")
          .text("LIFEFLOW DONATION REPORT", {
            align: "center",
            underline: true,
            underlineColor: primaryColor,
          })
          .moveDown(0.5);

        doc
          .fillColor(secondaryColor)
          .fontSize(10)
          .text(`Generated on: ${now.toLocaleString()}`, { align: "center" })
          .moveDown(2);

        // Summary Section with better styling
        doc
          .fillColor(secondaryColor)
          .fontSize(16)
          .font("Helvetica-Bold")
          .text("SUMMARY STATISTICS", { underline: true })
          .moveDown(1);

        // Summary table
        const summaryY = doc.y;
        const summaryCol1 = 50;
        const summaryCol2 = 350;

        // Table header
        doc
          .fillColor("#ffffff")
          .rect(summaryCol1 - 10, summaryY - 10, 400, 25)
          .fill(secondaryColor)
          .fillColor("#ffffff")
          .font("Helvetica-Bold")
          .text("Metric", summaryCol1, summaryY)
          .text("Value", summaryCol2, summaryY, { align: "right" })
          .moveDown(1);

        // Table rows with alternating background
        const summaryData = [
          {
            label: "Total Funds Raised",
            value: `$${(reportStats.totalFunds || 0).toLocaleString()}`,
          },
          {
            label: "Total Donations",
            value: (reportStats.count || 0).toLocaleString(),
          },
          {
            label: "Unique Donors",
            value: (reportStats.uniqueDonors?.length || 0).toLocaleString(),
          },
          {
            label: "Average Donation",
            value: `$${(reportStats.avgAmount || 0).toFixed(2)}`,
          },
        ];

        summaryData.forEach((row, i) => {
          const y = doc.y;
          doc
            .fillColor(i % 2 === 0 ? lightGray : "#ffffff")
            .rect(summaryCol1 - 10, y - 5, 400, 25)
            .fill()
            .fillColor(secondaryColor)
            .font("Helvetica")
            .text(row.label, summaryCol1, y)
            .text(row.value, summaryCol2, y, { align: "right" })
            .moveDown(1);
        });

        doc.moveDown(2);

        // Recent Donations Section
        doc
          .fillColor(secondaryColor)
          .fontSize(16)
          .font("Helvetica-Bold")
          .text("RECENT DONATIONS", { underline: true })
          .moveDown(1);

        // Donations table
        const tableTop = doc.y;
        const col1 = 50; // Date
        const col2 = 150; // Donor
        const col3 = 350; // Amount (right-aligned)
        const colWidth = 100;
        const rowHeight = 25;

        // Table header
        doc
          .fillColor("#ffffff")
          .rect(col1 - 10, tableTop - 10, 400, rowHeight)
          .fill(secondaryColor)
          .fillColor("#ffffff")
          .font("Helvetica-Bold")
          .text("Date", col1, tableTop)
          .text("Donor", col2, tableTop)
          .text("Amount", col3, tableTop, { width: colWidth, align: "right" })
          .moveDown(1);

        // Table rows
        recentDonations.forEach((donation, i) => {
          const y = tableTop + (i + 1) * rowHeight;

          doc
            .fillColor(i % 2 === 0 ? lightGray : "#ffffff")
            .rect(col1 - 10, y - 5, 400, rowHeight)
            .fill()
            .fillColor(secondaryColor)
            .font("Helvetica")
            .text(new Date(donation.createdAt).toLocaleDateString(), col1, y)
            .text(donation.userName || "Anonymous", col2, y)
            .text(`$${(donation.amount || 0).toLocaleString()}`, col3, y, {
              width: colWidth,
              align: "right",
            });
        });

        // Footer
        doc
          .fillColor(secondaryColor)
          .fontSize(10)
          .text("© LifeFlow Blood Donation System | Confidential", {
            align: "center",
            lineGap: 5,
          })
          .text(`Page ${doc.bufferedPageRange().count}`, { align: "center" });

        doc.end();
      } catch (error) {
        console.error("[GET /funds/report] Error:", error);
        res.status(500).json({
          success: false,
          message: "Failed to generate report",
          error:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        });
      }
    });

    // Create payment intent endpoint
    app.post("/api/payments/create-intent", async (req, res) => {
      const { amount, currency = "usd" } = req.body;

      // Validate amount
      if (!amount || isNaN(amount)) {
        return res.status(400).json({
          success: false,
          message: "Amount must be a valid number",
        });
      }

      const numericAmount = parseFloat(amount);
      if (numericAmount < 1) {
        return res.status(400).json({
          success: false,
          message: "Minimum donation amount is $1",
        });
      }

      try {
        const paymentIntent = await stripe.paymentIntents.create({
          amount: Math.round(numericAmount * 100), // Convert to cents
          currency,
          automatic_payment_methods: { enabled: true },
          metadata: {
            initiated_by: req.user?.email || "anonymous",
            purpose: "donation",
          },
        });

        res.json({
          success: true,
          clientSecret: paymentIntent.client_secret,
        });
      } catch (error) {
        console.error("Stripe intent error:", error);
        res.status(500).json({
          success: false,
          message: "Failed to create payment intent",
          error:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        });
      }
    });

    // Record donation endpoint
    app.post("/api/funds", verifyJWT, async (req, res) => {
      const {
        userEmail,
        userName,
        amount,
        currency = "usd",
        paymentIntentId,
        status = "succeeded",
        metadata = {},
      } = req.body;

      // Validate required fields
      if (!userEmail || !amount || !paymentIntentId) {
        return res.status(400).json({
          success: false,
          message: "Missing required fields",
          required: {
            userEmail: "string",
            amount: "number > 0",
            paymentIntentId: "string",
          },
        });
      }

      // Validate amount
      const numericAmount = parseFloat(amount);
      if (isNaN(numericAmount)) {
        return res.status(400).json({
          success: false,
          message: "Amount must be a valid number",
          received: amount,
        });
      }

      if (numericAmount <= 0) {
        return res.status(400).json({
          success: false,
          message: "Amount must be greater than 0",
          received: numericAmount,
        });
      }

      try {
        // Check for duplicate payment intent
        const existingDonation = await fundingCollection.findOne({
          paymentIntentId,
        });
        if (existingDonation) {
          return res.status(200).json({
            success: true,
            message: "Donation already recorded",
            data: {
              donationId: existingDonation._id,
              amount: existingDonation.amount,
            },
          });
        }

        // Create donation document
        const donation = {
          userEmail,
          userName: userName || "Anonymous Donor",
          amount: numericAmount,
          currency,
          paymentIntentId,
          status,
          metadata: {
            isAnonymous: !!metadata?.isAnonymous,
            campaign: metadata?.campaign || "general",
            ...metadata,
          },
          createdAt: new Date(),
          updatedAt: new Date(),
          receiptSent: false,
        };

        // Insert into database
        const result = await fundingCollection.insertOne(donation);

        // In production, you might want to:
        // 1. Send receipt email
        // 2. Update analytics
        // 3. Trigger any post-donation workflows

        res.status(201).json({
          success: true,
          message: "Donation recorded successfully",
          data: {
            donationId: result.insertedId,
            amount: donation.amount,
            currency: donation.currency,
            donor: donation.isAnonymous ? "Anonymous" : donation.userName,
          },
        });
      } catch (error) {
        console.error("[POST /api/funds] Error:", error);
        res.status(500).json({
          success: false,
          message: "Internal server error",
          error:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        });
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
          subject: "Thank you for contacting LifeFlow",
          html: `<h2>Hi ${name},</h2>
                 <p>We received your message:</p>
                 <blockquote>${message}</blockquote>
                 <p>We'll respond within 24h.</p><p>— LifeFlow Team</p>`,
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
    app.get("/api/users", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const email = req.decoded?.email;
        const { status, role, search, page = 1, limit = 10 } = req.query;

        const pageNum = parseInt(page);
        const limitNum = parseInt(limit);
        if (isNaN(pageNum) || isNaN(limitNum)) {
          return res
            .status(400)
            .json({ message: "Invalid pagination parameters" });
        }

        const user = await usersCollection.findOne({
          email: { $regex: new RegExp(`^${email}$`, "i") },
        });

        if (user?.role !== "admin") {
          return res.status(403).json({ message: "Forbidden: Admins only." });
        }

        const filter = {};
        if (status) filter.status = status;
        if (role) filter.role = role;
        if (search) {
          filter.$or = [
            { name: { $regex: search, $options: "i" } },
            { email: { $regex: search, $options: "i" } },
            { district: { $regex: search, $options: "i" } },
            { upazila: { $regex: search, $options: "i" } },
          ];
        }

        const users = await usersCollection
          .find(filter)
          .sort({ createdAt: -1 })
          .skip((pageNum - 1) * limitNum)
          .limit(limitNum)
          .toArray();

        const totalCount = await usersCollection.countDocuments(filter);

        res.status(200).json({
          users,
          pagination: {
            total: totalCount,
            page: pageNum,
            limit: limitNum,
            totalPages: Math.ceil(totalCount / limitNum),
          },
        });
      } catch (error) {
        console.error("Failed to fetch users:", error);
        res
          .status(500)
          .json({ message: "Failed to fetch users", error: error.message });
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
    // CHECK admin status of current user
    // ==============================
    app.get("/api/user/check-admin", verifyJWT, async (req, res) => {
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
    // GET specific user by email (self or admin)
    // ==============================
    app.get("/api/user/:email", verifyJWT, async (req, res) => {
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

        res.status(200).json({
          success: true,
          data: targetUser,
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch user", error });
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
        phone,
        role = "donor",
        status = "active",
        notifications = true,
        showDonorStatus = true,
        showBloodType = true,
        language = "en",
      } = req.body;

      // Input validation
      if (!email || !name || !firebaseUid) {
        return res.status(400).json({
          success: false,
          message: "Firebase UID, name and email are required",
          missingFields: [
            ...(!firebaseUid ? ["firebaseUid"] : []),
            ...(!email ? ["email"] : []),
            ...(!name ? ["name"] : []),
          ],
        });
      }

      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({
          success: false,
          message: "Invalid email format",
          field: "email",
        });
      }

      // Validate blood group if provided
      const validBloodGroups = [
        "A+",
        "A-",
        "B+",
        "B-",
        "AB+",
        "AB-",
        "O+",
        "O-",
        null,
      ];
      if (bloodGroup && !validBloodGroups.includes(bloodGroup)) {
        return res.status(400).json({
          success: false,
          message: "Invalid blood group",
          field: "bloodGroup",
          validOptions: validBloodGroups.filter((bg) => bg !== null),
        });
      }

      // Validate role
      const validRoles = ["donor", "recipient", "admin"];
      if (!validRoles.includes(role)) {
        return res.status(400).json({
          success: false,
          message: "Invalid user role",
          field: "role",
          validOptions: validRoles,
        });
      }

      try {
        // Check for existing user by email or firebaseUid
        const existingUser = await usersCollection.findOne({
          $or: [
            { email: { $regex: new RegExp(`^${email}$`, "i") } },
            { firebaseUid },
          ],
        });

        if (existingUser) {
          return res.status(200).json({
            success: true,
            message: "User already exists",
            data: {
              userId: existingUser._id,
              email: existingUser.email,
              name: existingUser.name,
              role: existingUser.role,
            },
          });
        }

        // Prepare new user document
        const newUser = {
          firebaseUid,
          name: name.trim(),
          email: email.toLowerCase().trim(),
          avatar: avatar || null,
          bloodGroup: bloodGroup || null,
          district: district || null,
          upazila: upazila || null,
          phone: phone || null,
          role,
          status,
          notifications,
          showDonorStatus,
          showBloodType,
          language,
          createdAt: new Date(),
          updatedAt: new Date(),
          lastLogin: new Date(),
          donationHistory: [],
          totalDonations: 0,
        };

        // Insert new user
        const result = await usersCollection.insertOne(newUser);

        // Create a clean response without sensitive data
        const userResponse = {
          userId: result.insertedId,
          email: newUser.email,
          name: newUser.name,
          role: newUser.role,
          status: newUser.status,
          createdAt: newUser.createdAt,
        };

        res.status(201).json({
          success: true,
          message: "User created successfully",
          data: userResponse,
        });

        // Optional: Send welcome email or other post-registration actions
        // await sendWelcomeEmail(newUser.email, newUser.name);
      } catch (error) {
        console.error("User creation error:", error);
        res.status(500).json({
          success: false,
          message: "User creation failed",
          error:
            process.env.NODE_ENV === "development"
              ? {
                  message: error.message,
                  stack: error.stack,
                }
              : undefined,
        });
      }
    });

    // ==============================
    // PATCH update user by email
    // ==============================
    app.patch("/api/user/:email", verifyJWT, async (req, res) => {
      const { email } = req.params;
      const updates = req.body;
      const requestingUserEmail = req.userEmail;

      // Validate that the requesting user can only update their own profile
      if (requestingUserEmail !== email) {
        return res.status(403).json({
          message: "Unauthorized - You can only update your own profile",
          success: false,
        });
      }

      // Define allowed fields that can be updated
      const allowedUpdates = [
        "name",
        "avatar",
        "district",
        "upazila",
        "bloodGroup",
        "phone",
        "notifications",
        "language",
        "showDonorStatus",
        "showBloodType",
      ];

      // Filter updates to only include allowed fields
      const filteredUpdates = Object.keys(updates)
        .filter((key) => allowedUpdates.includes(key))
        .reduce((obj, key) => {
          obj[key] = updates[key];
          return obj;
        }, {});

      // Check if there are valid updates after filtering
      if (Object.keys(filteredUpdates).length === 0) {
        return res.status(400).json({
          message: "No valid fields to update",
          success: false,
          allowedFields: allowedUpdates,
        });
      }

      try {
        const result = await usersCollection.updateOne(
          { email },
          { $set: filteredUpdates }
        );

        if (result.modifiedCount === 0) {
          return res.status(404).json({
            message: "User not found or no changes made",
            success: false,
          });
        }

        res.status(200).json({
          message: "User updated successfully",
          success: true,
          updatedFields: Object.keys(filteredUpdates),
        });
      } catch (error) {
        console.error("Update error:", error);
        res.status(500).json({
          message: "Update failed",
          success: false,
          error:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        });
      }
    });

    // ==============================
    // DELETE user by MongoDB ID
    // ==============================
    app.delete("/api/user/:id", verifyJWT, async (req, res) => {
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
    app.patch(
      "/api/user/:id/status",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
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
      }
    );
    // ==============================
    // PATCH update user role
    // ==============================
    app.patch(
      "/api/user/:id/role",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
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
      }
    );

    // GET all donation requests with filters + pagination
    app.get("/api/donations", async (req, res) => {
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
          urgencyLevel,
          contactPerson,
        } = req.query;
        const pageNumber = parseInt(page);
        const limitNumber = parseInt(limit);
        const skip = (pageNumber - 1) * limitNumber;

        // Validate pagination parameters
        if (isNaN(pageNumber) || pageNumber < 1) {
          return res.status(400).json({
            success: false,
            error: "Page must be a positive integer",
          });
        }
        if (isNaN(limitNumber) || limitNumber < 1 || limitNumber > 100) {
          return res.status(400).json({
            success: false,
            error: "Limit must be between 1 and 100",
          });
        }

        // Validate sort parameters
        const validSortFields = [
          "createdAt",
          "updatedAt",
          "date",
          "time",
          "recipientName",
          "bloodGroup",
          "hospitalName",
          "status",
        ];
        if (!validSortFields.includes(sortBy)) {
          return res.status(400).json({
            success: false,
            error: "Invalid sort field",
            validSortFields,
          });
        }
        const sort = { [sortBy]: sortOrder === "asc" ? 1 : -1 };

        // Build filter object
        const filter = {};

        // Status filter
        if (status) {
          const validStatuses = ["pending", "inprogress", "done", "canceled"];
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
        if (district)
          filter.recipientDistrict = { $regex: district, $options: "i" };
        if (upazila)
          filter.recipientUpazila = { $regex: upazila, $options: "i" };

        // Contact person filter
        if (contactPerson) {
          filter.contactPerson = { $regex: contactPerson, $options: "i" };
        }

        // Date range filter
        if (startDate || endDate) {
          filter.createdAt = {};
          if (startDate) {
            const start = new Date(startDate);
            if (isNaN(start.getTime())) {
              return res.status(400).json({
                success: false,
                error: "Invalid start date format",
              });
            }
            filter.createdAt.$gte = start;
          }
          if (endDate) {
            const end = new Date(endDate);
            if (isNaN(end.getTime())) {
              return res.status(400).json({
                success: false,
                error: "Invalid end date format",
              });
            }
            // Set end time to end of day
            end.setHours(23, 59, 59, 999);
            filter.createdAt.$lte = end;
          }
        }

        // Search filter
        if (search) {
          filter.$or = [
            { recipientName: { $regex: search, $options: "i" } },
            { hospitalName: { $regex: search, $options: "i" } },
            { hospitalAddress: { $regex: search, $options: "i" } },
            { reason: { $regex: search, $options: "i" } },
            { message: { $regex: search, $options: "i" } },
            { contactPerson: { $regex: search, $options: "i" } },
            { contactEmail: { $regex: search, $options: "i" } },
          ];
        }

        // Execute queries in parallel
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
          filters: {
            status,
            bloodGroup,
            district,
            upazila,
            contactPerson,
            startDate,
            endDate,
            search,
            sortBy,
            sortOrder,
          },
        });
      } catch (error) {
        console.error("Error fetching donation requests:", error);
        res.status(500).json({
          success: false,
          error: "Internal server error",
          message:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        });
      }
    });

    // GET all emergency requests with filters + pagination
    app.get("/api/emergency-requests", async (req, res) => {
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
          urgencyLevel,
          contactPerson,
        } = req.query;
        const pageNumber = parseInt(page);
        const limitNumber = parseInt(limit);
        const skip = (pageNumber - 1) * limitNumber;

        // Validate pagination parameters
        if (isNaN(pageNumber) || pageNumber < 1) {
          return res.status(400).json({
            success: false,
            error: "Page must be a positive integer",
          });
        }
        if (isNaN(limitNumber) || limitNumber < 1 || limitNumber > 100) {
          return res.status(400).json({
            success: false,
            error: "Limit must be between 1 and 100",
          });
        }

        // Validate sort parameters
        const validSortFields = [
          "createdAt",
          "updatedAt",
          "date",
          "time",
          "patientName",
          "bloodGroup",
          "hospitalName",
          "urgencyLevel",
          "status",
        ];
        if (!validSortFields.includes(sortBy)) {
          return res.status(400).json({
            success: false,
            error: "Invalid sort field",
            validSortFields,
          });
        }
        const sort = { [sortBy]: sortOrder === "asc" ? 1 : -1 };

        // Build filter object
        const filter = {};

        // Status filter
        if (status) {
          const validStatuses = ["pending", "inprogress", "done", "canceled"];
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
        if (district)
          filter.recipientDistrict = { $regex: district, $options: "i" };
        if (upazila)
          filter.recipientUpazila = { $regex: upazila, $options: "i" };

        // Urgency level filter
        if (urgencyLevel) {
          const validUrgencyLevels = ["low", "medium", "high", "critical"];
          if (validUrgencyLevels.includes(urgencyLevel)) {
            filter.urgencyLevel = urgencyLevel;
          } else {
            return res.status(400).json({
              success: false,
              error: "Invalid urgency level",
              validUrgencyLevels,
            });
          }
        }

        // Contact person filter
        if (contactPerson) {
          filter.contactPerson = { $regex: contactPerson, $options: "i" };
        }

        // Date range filter
        if (startDate || endDate) {
          filter.createdAt = {};
          if (startDate) {
            const start = new Date(startDate);
            if (isNaN(start.getTime())) {
              return res.status(400).json({
                success: false,
                error: "Invalid start date format",
              });
            }
            filter.createdAt.$gte = start;
          }
          if (endDate) {
            const end = new Date(endDate);
            if (isNaN(end.getTime())) {
              return res.status(400).json({
                success: false,
                error: "Invalid end date format",
              });
            }
            // Set end time to end of day
            end.setHours(23, 59, 59, 999);
            filter.createdAt.$lte = end;
          }
        }

        // Search filter
        if (search) {
          filter.$or = [
            { patientName: { $regex: search, $options: "i" } },
            { hospitalName: { $regex: search, $options: "i" } },
            { hospitalAddress: { $regex: search, $options: "i" } },
            { reason: { $regex: search, $options: "i" } },
            { message: { $regex: search, $options: "i" } },
            { contactPerson: { $regex: search, $options: "i" } },
            { contactEmail: { $regex: search, $options: "i" } },
          ];
        }

        // Execute queries in parallel
        const [requests, totalCount] = await Promise.all([
          emergencyRequestCollection
            .find(filter)
            .sort(sort)
            .skip(skip)
            .limit(limitNumber)
            .toArray(),
          emergencyRequestCollection.countDocuments(filter),
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
          filters: {
            status,
            bloodGroup,
            district,
            upazila,
            urgencyLevel,
            contactPerson,
            startDate,
            endDate,
            search,
            sortBy,
            sortOrder,
          },
        });
      } catch (error) {
        console.error("Error fetching emergency requests:", error);
        res.status(500).json({
          success: false,
          error: "Internal server error",
          message:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        });
      }
    });

    // GET donations made by current user (as donor)
    app.get("/api/donations/my-donations", verifyJWT, async (req, res) => {
      try {
        const email = req.userEmail;
        const {
          status,
          page = 1,
          limit = 10,
          sortBy = "donatedAt",
          sortOrder = "desc",
        } = req.query;
        const pageNumber = parseInt(page);
        const limitNumber = parseInt(limit);
        const skip = (pageNumber - 1) * limitNumber;

        // Validate pagination parameters
        if (isNaN(pageNumber) || pageNumber < 1) {
          return res.status(400).json({
            success: false,
            error: "Page must be a positive integer",
          });
        }
        if (isNaN(limitNumber) || limitNumber < 1 || limitNumber > 100) {
          return res.status(400).json({
            success: false,
            error: "Limit must be between 1 and 100",
          });
        }

        // Build filter
        const filter = { "donor.email": email };

        // Add status filter if provided
        if (status && status !== "all") {
          const validStatuses = ["inprogress", "done"];
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

        // Validate sort parameters
        const validSortFields = [
          "donatedAt",
          "createdAt",
          "hospitalName",
          "bloodGroup",
        ];
        if (!validSortFields.includes(sortBy)) {
          return res.status(400).json({
            success: false,
            error: "Invalid sort field",
            validSortFields,
          });
        }
        const sort = { [sortBy]: sortOrder === "asc" ? 1 : -1 };

        // Query both collections and combine results
        const [donationRequests, emergencyRequests] = await Promise.all([
          donationRequestCollection
            .find(filter)
            .sort(sort)
            .skip(skip)
            .limit(limitNumber)
            .toArray(),
          emergencyRequestCollection
            .find(filter)
            .sort(sort)
            .skip(skip)
            .limit(limitNumber)
            .toArray(),
        ]);

        // Combine results and add requestType field
        const combinedRequests = [
          ...donationRequests.map((req) => ({
            ...req,
            requestType: "donation",
          })),
          ...emergencyRequests.map((req) => ({
            ...req,
            requestType: "emergency",
          })),
        ];

        // Sort combined results if needed
        combinedRequests.sort((a, b) => {
          if (sort[sortBy] === 1) {
            return a[sortBy] > b[sortBy] ? 1 : -1;
          } else {
            return a[sortBy] < b[sortBy] ? 1 : -1;
          }
        });

        // Get total counts
        const [donationCount, emergencyCount] = await Promise.all([
          donationRequestCollection.countDocuments(filter),
          emergencyRequestCollection.countDocuments(filter),
        ]);

        const totalCount = donationCount + emergencyCount;
        const totalPages = Math.ceil(totalCount / limitNumber);

        res.json({
          success: true,
          data: combinedRequests,
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
        console.error("Error fetching user donations:", error);
        res.status(500).json({
          success: false,
          error: "Internal server error",
          message:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        });
      }
    });

    // GET all donation requests by requester email
    app.get(
      "/api/donations/:email/my-requests",
      verifyJWT,
      async (req, res) => {
        try {
          const email = req.params.email;
          const {
            status,
            page = 1,
            limit = 10,
            sortBy = "createdAt",
            sortOrder = "desc",
            urgencyLevel,
            bloodGroup,
          } = req.query;
          const pageNumber = parseInt(page);
          const limitNumber = parseInt(limit);
          const skip = (pageNumber - 1) * limitNumber;

          // Validate pagination parameters
          if (isNaN(pageNumber) || pageNumber < 1) {
            return res.status(400).json({
              success: false,
              error: "Page must be a positive integer",
            });
          }
          if (isNaN(limitNumber) || limitNumber < 1 || limitNumber > 100) {
            return res.status(400).json({
              success: false,
              error: "Limit must be between 1 and 100",
            });
          }

          // Build filter
          const filter = { requesterEmail: email };

          // Add status filter if provided
          if (status && status !== "all") {
            const validStatuses = ["pending", "inprogress", "done", "canceled"];
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

          // Add urgency level filter (only for emergency requests)
          if (urgencyLevel) {
            const validUrgencyLevels = ["low", "medium", "high", "critical"];
            if (validUrgencyLevels.includes(urgencyLevel)) {
              // This will be applied separately to emergency requests
            } else {
              return res.status(400).json({
                success: false,
                error: "Invalid urgency level",
                validUrgencyLevels,
              });
            }
          }

          // Add blood group filter
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

          // Validate sort parameters
          const validSortFields = [
            "createdAt",
            "updatedAt",
            "date",
            "time",
            "hospitalName",
            "status",
          ];
          if (!validSortFields.includes(sortBy)) {
            return res.status(400).json({
              success: false,
              error: "Invalid sort field",
              validSortFields,
            });
          }
          const sort = { [sortBy]: sortOrder === "asc" ? 1 : -1 };

          // Query both collections
          const donationFilter = { ...filter };
          const emergencyFilter = { ...filter };

          // Add urgency level filter to emergency requests if provided
          if (urgencyLevel) {
            emergencyFilter.urgencyLevel = urgencyLevel;
          }

          const [donationRequests, emergencyRequests] = await Promise.all([
            donationRequestCollection
              .find(donationFilter)
              .sort(sort)
              .skip(skip)
              .limit(limitNumber)
              .toArray(),
            emergencyRequestCollection
              .find(emergencyFilter)
              .sort(sort)
              .skip(skip)
              .limit(limitNumber)
              .toArray(),
          ]);

          // Combine results and add requestType field
          const combinedRequests = [
            ...donationRequests.map((req) => ({
              ...req,
              requestType: "donation",
            })),
            ...emergencyRequests.map((req) => ({
              ...req,
              requestType: "emergency",
            })),
          ];

          // Sort combined results if needed
          combinedRequests.sort((a, b) => {
            if (sort[sortBy] === 1) {
              return a[sortBy] > b[sortBy] ? 1 : -1;
            } else {
              return a[sortBy] < b[sortBy] ? 1 : -1;
            }
          });

          // Get total counts
          const [donationCount, emergencyCount] = await Promise.all([
            donationRequestCollection.countDocuments(donationFilter),
            emergencyRequestCollection.countDocuments(emergencyFilter),
          ]);

          const totalCount = donationCount + emergencyCount;
          const totalPages = Math.ceil(totalCount / limitNumber);

          res.json({
            success: true,
            data: combinedRequests,
            pagination: {
              totalItems: totalCount,
              totalPages,
              currentPage: pageNumber,
              itemsPerPage: limitNumber,
              hasNext: pageNumber < totalPages,
              hasPrevious: pageNumber > 1,
            },
            filters: {
              status,
              urgencyLevel,
              bloodGroup,
              sortBy,
              sortOrder,
            },
          });
        } catch (error) {
          console.error("Error fetching user requests:", error);
          res.status(500).json({
            success: false,
            error: "Internal server error",
            message:
              process.env.NODE_ENV === "development"
                ? error.message
                : undefined,
          });
        }
      }
    );

    // GET recent donation requests by requester email
    app.get("/api/donations/recent/:email", verifyJWT, async (req, res) => {
      try {
        const email = req.params.email;
        const { limit = 3 } = req.query;
        const limitNumber = parseInt(limit);

        // Validate limit parameter
        if (isNaN(limitNumber) || limitNumber < 1 || limitNumber > 10) {
          return res.status(400).json({
            success: false,
            error: "Limit must be between 1 and 10",
          });
        }

        // Query both collections
        const [donationRequests, emergencyRequests] = await Promise.all([
          donationRequestCollection
            .find({ requesterEmail: email })
            .sort({ createdAt: -1 })
            .limit(limitNumber)
            .toArray(),
          emergencyRequestCollection
            .find({ requesterEmail: email })
            .sort({ createdAt: -1 })
            .limit(limitNumber)
            .toArray(),
        ]);

        // Combine results and add requestType field
        const combinedRequests = [
          ...donationRequests.map((req) => ({
            ...req,
            requestType: "donation",
          })),
          ...emergencyRequests.map((req) => ({
            ...req,
            requestType: "emergency",
          })),
        ];

        // Sort combined results by creation date
        combinedRequests.sort((a, b) => b.createdAt - a.createdAt);

        // Limit the total number of results
        const limitedRequests = combinedRequests.slice(0, limitNumber);

        res.json({
          success: true,
          data: limitedRequests,
          count: limitedRequests.length,
        });
      } catch (error) {
        console.error("Error fetching recent requests:", error);
        res.status(500).json({
          success: false,
          error: "Internal server error",
          message:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        });
      }
    });

    // GET single request by ID (works for both emergency and donation requests)
    app.get("/api/requests/:id", verifyJWT, async (req, res) => {
      try {
        const id = req.params.id;

        // Validate ObjectId
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({
            success: false,
            error: "Invalid ID format",
          });
        }

        // Try to find in donation requests collection first
        let request = await donationRequestCollection.findOne({
          _id: new ObjectId(id),
        });

        // If not found, try emergency requests collection
        if (!request) {
          request = await emergencyRequestCollection.findOne({
            _id: new ObjectId(id),
          });
        }

        if (!request) {
          return res.status(404).json({
            success: false,
            error: "Request not found",
          });
        }

        // Add requestType field to distinguish between request types
        if (request.patientName) {
          request.requestType = "emergency";
        } else {
          request.requestType = "donation";
        }

        res.json({
          success: true,
          data: request,
        });
      } catch (error) {
        console.error("Error fetching request:", error);
        res.status(500).json({
          success: false,
          error: "Internal server error",
          message:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        });
      }
    });

    // POST new emergency request
    app.post("/api/emergency-request", async (req, res) => {
      try {
        const {
          // Patient Information
          patientName,
          patientAge,
          bloodGroup,
          unitsRequired,
          // Hospital Information
          hospitalName,
          hospitalAddress,
          recipientDistrict,
          recipientUpazila,
          // Contact Information
          contactPerson,
          contactPhone,
          contactEmail,
          // Request Details
          date,
          time,
          urgencyLevel,
          reason,
          message,
          // Requester Information (from form)
          requesterName,
          requesterEmail,
        } = req.body;

        // Validate required fields
        const requiredFields = [
          patientName,
          patientAge,
          bloodGroup,
          unitsRequired,
          hospitalName,
          hospitalAddress,
          contactPerson,
          contactPhone,
          contactEmail,
          date,
          time,
          reason,
        ];

        if (
          requiredFields.some(
            (field) => !field || field.toString().trim() === ""
          )
        ) {
          return res.status(400).json({
            success: false,
            error: "All required fields must be filled",
          });
        }

        // Validate specific field formats
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(contactEmail)) {
          return res.status(400).json({
            success: false,
            error: "Invalid email format",
          });
        }

        const phoneRegex = /^[\d\s\-\+\(\)]+$/;
        if (!phoneRegex.test(contactPhone) || contactPhone.length < 10) {
          return res.status(400).json({
            success: false,
            error: "Invalid phone number",
          });
        }

        // Validate age
        const age = parseInt(patientAge);
        if (isNaN(age) || age < 1 || age > 120) {
          return res.status(400).json({
            success: false,
            error: "Patient age must be between 1 and 120",
          });
        }

        // Validate units required
        const units = parseInt(unitsRequired);
        if (isNaN(units) || units < 1 || units > 10) {
          return res.status(400).json({
            success: false,
            error: "Units required must be between 1 and 10",
          });
        }

        // Validate date
        const requestDate = new Date(date);
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        if (requestDate < today) {
          return res.status(400).json({
            success: false,
            error: "Required date cannot be in the past",
          });
        }

        // Validate time
        const timeRegex = /^([01]?[0-9]|2[0-3]):[0-5][0-9]$/;
        if (!timeRegex.test(time)) {
          return res.status(400).json({
            success: false,
            error: "Invalid time format (HH:MM)",
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
        if (!validBloodGroups.includes(bloodGroup)) {
          return res.status(400).json({
            success: false,
            error: "Invalid blood group",
          });
        }

        // Validate urgency level
        const validUrgencyLevels = ["low", "medium", "high", "critical"];
        if (urgencyLevel && !validUrgencyLevels.includes(urgencyLevel)) {
          return res.status(400).json({
            success: false,
            error: "Invalid urgency level",
          });
        }

        // Create new emergency request object
        const newRequest = {
          // Patient Information
          patientName: patientName.trim(),
          patientAge: age,
          bloodGroup,
          unitsRequired: units,
          // Hospital Information
          hospitalName: hospitalName.trim(),
          hospitalAddress: hospitalAddress.trim(),
          recipientDistrict: recipientDistrict?.trim() || "",
          recipientUpazila: recipientUpazila?.trim() || "",
          // Contact Information
          contactPerson: contactPerson.trim(),
          contactPhone: contactPhone.trim(),
          contactEmail: contactEmail.trim(),
          // Request Details
          date: requestDate,
          time: time.trim(),
          urgencyLevel: urgencyLevel || "medium",
          reason: reason.trim(),
          message: message.trim(),
          // Requester Information
          requesterName: requesterName?.trim() || contactPerson.trim(),
          requesterEmail: requesterEmail?.trim() || contactEmail.trim(),
          // Status and Timestamps
          status: "pending",
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        // Insert into emergency requests collection
        const result = await emergencyRequestCollection.insertOne(newRequest);

        // Return success response
        res.status(201).json({
          success: true,
          requestId: result.insertedId,
          message: "Emergency request created successfully",
          data: {
            id: result.insertedId,
            patientName: newRequest.patientName,
            bloodGroup: newRequest.bloodGroup,
            hospitalName: newRequest.hospitalName,
            status: newRequest.status,
          },
        });
      } catch (error) {
        console.error("Error creating emergency request:", error);
        res.status(500).json({
          success: false,
          error: "Internal server error",
        });
      }
    });

    // POST new donation request
    app.post("/api/donation-request", async (req, res) => {
      try {
        const {
          // Recipient Information
          recipientName,
          recipientAge,
          bloodGroup,
          unitsRequired,
          // Hospital Information
          hospitalName,
          hospitalAddress,
          recipientDistrict,
          recipientUpazila,
          // Contact Information
          contactPerson,
          contactPhone,
          contactEmail,
          // Request Details
          date,
          time,
          reason,
          message,
          // Requester Information (from form)
          requesterName,
          requesterEmail,
        } = req.body;

        // Validate required fields
        const requiredFields = [
          recipientName,
          recipientAge,
          bloodGroup,
          unitsRequired,
          hospitalName,
          hospitalAddress,
          contactPerson,
          contactPhone,
          contactEmail,
          date,
          time,
          reason,
        ];

        if (
          requiredFields.some(
            (field) => !field || field.toString().trim() === ""
          )
        ) {
          return res.status(400).json({
            success: false,
            error: "All required fields must be filled",
          });
        }

        // Validate specific field formats
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(contactEmail)) {
          return res.status(400).json({
            success: false,
            error: "Invalid email format",
          });
        }

        const phoneRegex = /^[\d\s\-\+\(\)]+$/;
        if (!phoneRegex.test(contactPhone) || contactPhone.length < 10) {
          return res.status(400).json({
            success: false,
            error: "Invalid phone number",
          });
        }

        // Validate age
        const age = parseInt(recipientAge);
        if (isNaN(age) || age < 1 || age > 120) {
          return res.status(400).json({
            success: false,
            error: "Recipient age must be between 1 and 120",
          });
        }

        // Validate units required
        const units = parseInt(unitsRequired);
        if (isNaN(units) || units < 1 || units > 10) {
          return res.status(400).json({
            success: false,
            error: "Units required must be between 1 and 10",
          });
        }

        // Validate date
        const requestDate = new Date(date);
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        if (requestDate < today) {
          return res.status(400).json({
            success: false,
            error: "Required date cannot be in the past",
          });
        }

        // Validate time
        const timeRegex = /^([01]?[0-9]|2[0-3]):[0-5][0-9]$/;
        if (!timeRegex.test(time)) {
          return res.status(400).json({
            success: false,
            error: "Invalid time format (HH:MM)",
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
        if (!validBloodGroups.includes(bloodGroup)) {
          return res.status(400).json({
            success: false,
            error: "Invalid blood group",
          });
        }

        // Create new donation request object
        const newRequest = {
          // Recipient Information
          recipientName: recipientName.trim(),
          recipientAge: age,
          bloodGroup,
          unitsRequired: units,
          // Hospital Information
          hospitalName: hospitalName.trim(),
          hospitalAddress: hospitalAddress.trim(),
          recipientDistrict: recipientDistrict?.trim() || "",
          recipientUpazila: recipientUpazila?.trim() || "",
          // Contact Information
          contactPerson: contactPerson.trim(),
          contactPhone: contactPhone.trim(),
          contactEmail: contactEmail.trim(),
          // Request Details
          date: requestDate,
          time: time.trim(),
          reason: reason.trim(),
          message: message.trim(),
          // Requester Information
          requesterName: requesterName?.trim() || contactPerson.trim(),
          requesterEmail: requesterEmail?.trim() || contactEmail.trim(),
          // Status and Timestamps
          status: "pending",
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        // Insert into donation requests collection
        const result = await donationRequestCollection.insertOne(newRequest);

        // Return success response
        res.status(201).json({
          success: true,
          requestId: result.insertedId,
          message: "Donation request created successfully",
          data: {
            id: result.insertedId,
            recipientName: newRequest.recipientName,
            bloodGroup: newRequest.bloodGroup,
            hospitalName: newRequest.hospitalName,
            status: newRequest.status,
          },
        });
      } catch (error) {
        console.error("Error creating donation request:", error);
        res.status(500).json({
          success: false,
          error: "Internal server error",
        });
      }
    });

    // PATCH request (update) - works for both emergency and donation requests
    app.patch("/api/requests/:id", verifyJWT, async (req, res) => {
      try {
        const { id } = req.params;
        const updateData = req.body;

        // Validate ObjectId
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({
            success: false,
            error: "Invalid ID format",
          });
        }

        // Determine which collection to use
        let collection;
        let request = await donationRequestCollection.findOne({
          _id: new ObjectId(id),
        });

        if (request) {
          collection = donationRequestCollection;
        } else {
          request = await emergencyRequestCollection.findOne({
            _id: new ObjectId(id),
          });
          if (request) {
            collection = emergencyRequestCollection;
          } else {
            return res.status(404).json({
              success: false,
              error: "Request not found",
            });
          }
        }

        // Only allow updates if status is pending
        if (request.status !== "pending") {
          return res.status(400).json({
            success: false,
            error: "Only pending requests can be updated",
          });
        }

        // Add updatedAt timestamp
        updateData.updatedAt = new Date();

        // Update the request
        const result = await collection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({
            success: false,
            error: "Request not found",
          });
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
        console.error("Error updating request:", error);
        res.status(500).json({
          success: false,
          error: "Internal server error",
        });
      }
    });

    // PATCH request (confirm donation) - works for both emergency and donation requests
    app.patch("/api/requests/:id/donate", verifyJWT, async (req, res) => {
      try {
        const { id } = req.params;
        const { status, donor, donationId } = req.body;

        // Validate ObjectId
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({
            success: false,
            error: "Invalid ID format",
          });
        }

        // Validate required fields
        if (status !== "inprogress") {
          return res.status(400).json({
            success: false,
            error: "Status must be 'inprogress' for donation",
          });
        }

        if (!donor || !donor.email || !donor.name) {
          return res.status(400).json({
            success: false,
            error: "Donor information is required",
          });
        }

        // Validate donor email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(donor.email)) {
          return res.status(400).json({
            success: false,
            error: "Invalid donor email format",
          });
        }

        // Determine which collection to use
        let collection;
        let request = await donationRequestCollection.findOne({
          _id: new ObjectId(id),
        });

        if (request) {
          collection = donationRequestCollection;
        } else {
          request = await emergencyRequestCollection.findOne({
            _id: new ObjectId(id),
          });
          if (request) {
            collection = emergencyRequestCollection;
          } else {
            return res.status(404).json({
              success: false,
              error: "Request not found",
            });
          }
        }

        // Prevent self-donation
        if (request.requesterEmail === donor.email) {
          return res.status(400).json({
            success: false,
            error: "Cannot donate to your own request",
          });
        }

        // Check if request is still available for donation
        if (request.status !== "pending") {
          return res.status(400).json({
            success: false,
            error: `Request is no longer available for donation (current status: ${request.status})`,
          });
        }

        // Prepare update with additional metadata
        const updateDoc = {
          $set: {
            status,
            donationId,
            donor: {
              ...donor,
              donatedAt: new Date(),
            },
            updatedAt: new Date(),
          },
        };

        // Update the request
        const result = await collection.updateOne(
          { _id: new ObjectId(id) },
          updateDoc
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({
            success: false,
            error: "Request not found",
          });
        }

        // Return success response
        res.json({
          success: result.modifiedCount === 1,
          message: "Donation confirmed successfully",
          data: {
            donationId: id,
            donor: donor.email,
            status,
            donatedAt: new Date(),
          },
        });
      } catch (error) {
        console.error("Error updating donation status:", error);
        res.status(500).json({
          success: false,
          error: "Internal server error",
          details:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        });
      }
    });

    // Update request status (admin only) - works for both emergency and donation requests
    app.patch("/api/requests/status/:id", verifyJWT, async (req, res) => {
      try {
        const { id } = req.params;
        const { status, notes } = req.body;
        const validStatuses = ["pending", "inprogress", "done", "canceled"];

        if (!validStatuses.includes(status)) {
          return res.status(400).json({
            success: false,
            error: "Invalid status",
            validStatuses,
          });
        }

        // Determine which collection to use
        let collection;
        let request = await donationRequestCollection.findOne({
          _id: new ObjectId(id),
        });

        if (request) {
          collection = donationRequestCollection;
        } else {
          request = await emergencyRequestCollection.findOne({
            _id: new ObjectId(id),
          });
          if (request) {
            collection = emergencyRequestCollection;
          } else {
            return res.status(404).json({
              success: false,
              error: "Request not found",
            });
          }
        }

        // Prepare update data
        const updateData = {
          status,
          updatedAt: new Date(),
        };

        // Add notes if provided
        if (notes !== undefined) {
          updateData.notes = notes.trim();
        }

        // Add completion timestamp if status is "done"
        if (status === "done") {
          updateData.completedAt = new Date();
        }

        // Update the request
        const result = await collection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData }
        );

        if (result.modifiedCount === 0) {
          return res.status(404).json({
            success: false,
            error: "Request not found or no changes made",
          });
        }

        res.json({
          success: true,
          message: "Status updated successfully",
          updatedId: id,
          newStatus: status,
          updatedData: updateData,
        });
      } catch (error) {
        console.error("Error updating request status:", error);
        res.status(500).json({
          success: false,
          error: "Internal server error",
          message: error.message,
        });
      }
    });

    // DELETE request - works for both emergency and donation requests
    app.delete("/api/requests/:id", verifyJWT, async (req, res) => {
      try {
        const { id } = req.params;

        // Validate ObjectId
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({
            success: false,
            error: "Invalid ID format",
          });
        }

        // Determine which collection to use
        let collection;
        let request = await donationRequestCollection.findOne({
          _id: new ObjectId(id),
        });

        if (request) {
          collection = donationRequestCollection;
        } else {
          request = await emergencyRequestCollection.findOne({
            _id: new ObjectId(id),
          });
          if (request) {
            collection = emergencyRequestCollection;
          } else {
            return res.status(404).json({
              success: false,
              error: "Request not found",
            });
          }
        }

        // Only allow deletion of pending requests
        if (request.status !== "pending") {
          return res.status(400).json({
            success: false,
            error: `Cannot delete request with status: ${request.status}`,
          });
        }

        // Delete the request
        const result = await collection.deleteOne({
          _id: new ObjectId(id),
        });

        res.json({
          success: result.deletedCount === 1,
          message:
            result.deletedCount === 1
              ? "Request deleted successfully"
              : "Failed to delete request",
        });
      } catch (error) {
        console.error("Error deleting request:", error);
        res.status(500).json({
          success: false,
          error: "Internal server error",
          message: error.message,
        });
      }
    });

    // Get all blogs with filtering and pagination
    app.get("/api/blogs", async (req, res) => {
      try {
        const {
          status = "published",
          search = "",
          authorId,
          page = 1,
          limit = 10,
          sort = "-createdAt",
        } = req.query;

        const numericPage = parseInt(page);
        const numericLimit = parseInt(limit);

        const filter = {};

        // ✅ Restrict to only 'draft' and 'published'
        if (status === "all") {
          filter.status = { $in: ["draft", "published"] };
        } else if (["draft", "published"].includes(status)) {
          filter.status = status;
        } else {
          return res.status(400).json({
            success: false,
            message:
              "Invalid status filter. Must be 'draft', 'published', or 'all'.",
          });
        }

        // ✅ Filter by authorId if present
        if (authorId) {
          filter.authorId = authorId;
        }

        // ✅ Full-text search on title, content, or author
        if (search) {
          filter.$or = [
            { title: { $regex: search, $options: "i" } },
            { content: { $regex: search, $options: "i" } },
            { author: { $regex: search, $options: "i" } },
          ];
        }

        // ✅ Sorting
        const sortOption = {};
        if (sort.startsWith("-")) {
          sortOption[sort.substring(1)] = -1;
        } else {
          sortOption[sort] = 1;
        }

        // ✅ Pagination calculation
        const skip = (numericPage - 1) * numericLimit;

        // ✅ Only send needed fields
        const projection = {
          _id: 1,
          title: 1,
          thumbnail: 1,
          slug: 1,
          status: 1,
          views: 1,
          author: 1,
          authorImage: 1,
          authorEmail: 1,
          createdAt: 1,
          content: 1, // Add if content snippet is needed in frontend preview
        };

        const totalBlogs = await blogsCollection.countDocuments(filter);
        const totalPages = Math.ceil(totalBlogs / numericLimit);

        const blogs = await blogsCollection
          .find(filter)
          .project(projection)
          .sort(sortOption)
          .skip(skip)
          .limit(numericLimit)
          .toArray();

        res.json({
          success: true,
          count: blogs.length,
          total: totalBlogs,
          page: numericPage,
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

    app.get("/api/blogs/:id", verifyJWT, async (req, res) => {
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
    app.post("/api/blogs", verifyJWT, async (req, res) => {
      try {
        const { title, content, thumbnail, authorId, authorImage, slug } =
          req.body;

        // ✅ Validate required fields
        if (
          !title ||
          !content ||
          !thumbnail ||
          !authorId ||
          !slug ||
          !authorImage
        ) {
          return res.status(400).json({
            success: false,
            message:
              "Title, content, thumbnail, slug, and authorId are required",
          });
        }

        // ✅ Find user by Firebase UID
        const author = await usersCollection.findOne({
          firebaseUid: authorId,
        });

        if (!author) {
          return res.status(404).json({
            success: false,
            message: "Author not found",
          });
        }

        // ✅ Create blog object
        const newBlog = {
          title,
          content,
          thumbnail,
          slug,
          authorImage,
          author: author.name || "Anonymous",
          authorId: author.firebaseUid,
          authorEmail: author.email || "unknown@example.com",
          status: "draft",
          views: 0,
          comments: [],
          likes: [],
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        // ✅ Save to DB
        const result = await blogsCollection.insertOne(newBlog);

        res.status(201).json({
          success: true,
          data: {
            ...newBlog,
            _id: result.insertedId,
          },
        });
      } catch (error) {
        console.error("Error creating blog:", error);
        res.status(500).json({
          success: false,
          message: "Server error creating blog",
          error: error.message,
        });
      }
    });

    // Update blog
    app.put("/api/blogs/:id", verifyJWT, async (req, res) => {
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

    // Like/unlike a blog
    app.patch("/api/blogs/:id/like", verifyJWT, async (req, res) => {
      try {
        if (!ObjectId.isValid(req.params.id)) {
          return res.status(400).json({
            success: false,
            message: "Invalid blog ID",
          });
        }
        const { authorId } = req.body;
        if (!authorId) {
          return res.status(400).json({
            success: false,
            message: "User ID is required",
          });
        }

        const blogId = new ObjectId(req.params.id);
        const blog = await blogsCollection.findOne({ _id: blogId });

        if (!blog) {
          return res.status(404).json({
            success: false,
            message: "Blog not found",
          });
        }

        // Check if user already liked the blog
        const likeIndex = blog.likes.findIndex((id) => id === authorId);
        let update;
        let isLiked;

        if (likeIndex === -1) {
          // Add like
          update = { $push: { likes: authorId }, $inc: { likesCount: 1 } };
          isLiked = true;
        } else {
          // Remove like
          update = { $pull: { likes: authorId }, $inc: { likesCount: -1 } };
          isLiked = false;
        }

        const result = await blogsCollection.updateOne({ _id: blogId }, update);

        if (result.modifiedCount === 0) {
          return res.status(400).json({
            success: false,
            message: "Failed to update like status",
          });
        }

        // Get updated likes count
        const updatedBlog = await blogsCollection.findOne({ _id: blogId });

        res.json({
          success: true,
          isLiked,
          likesCount: updatedBlog.likesCount || updatedBlog.likes.length,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Failed to update blog like",
          error: error.message,
        });
      }
    });

    // Bookmark/unbookmark a blog
    app.patch("/api/blogs/:id/bookmark", verifyJWT, async (req, res) => {
      try {
        if (!ObjectId.isValid(req.params.id)) {
          return res.status(400).json({
            success: false,
            message: "Invalid blog ID",
          });
        }

        const { authorId } = req.body;
        if (!authorId) {
          return res.status(400).json({
            success: false,
            message: "User ID is required",
          });
        }

        // Find user document
        const user = await usersCollection.findOne({ firebaseUid: authorId });
        if (!user) {
          return res.status(404).json({
            success: false,
            message: "User not found",
          });
        }

        const blogId = req.params.id;
        const bookmarkIndex = user.bookmarks?.indexOf(blogId) ?? -1;
        let update;
        let isBookmarked;

        if (bookmarkIndex === -1) {
          // Add bookmark
          update = { $addToSet: { bookmarks: blogId } };
          isBookmarked = true;
        } else {
          // Remove bookmark
          update = { $pull: { bookmarks: blogId } };
          isBookmarked = false;
        }

        const result = await usersCollection.updateOne(
          { firebaseUid: authorId },
          update
        );

        if (result.modifiedCount === 0) {
          return res.status(400).json({
            success: false,
            message: "Failed to update bookmark status",
          });
        }

        res.json({
          success: true,
          isBookmarked,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Failed to update bookmark",
          error: error.message,
        });
      }
    });

    // Update blog status
    app.patch("/api/blogs/:id/status", verifyJWT, async (req, res) => {
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
    app.patch("/api/blogs/:id/views", verifyJWT, async (req, res) => {
      try {
        const { id } = req.params;

        // Validate ID format first
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({
            success: false,
            message: "Invalid blog ID format",
          });
        }

        const blogId = new ObjectId(id);
        const ip = req.ip || req.connection.remoteAddress;
        const userAgent = req.headers["user-agent"] || "unknown";
        const referrer = req.headers.referer || "direct";
        const now = new Date();

        // Additional check if blog exists
        const blogExists = await blogsCollection.findOne(
          { _id: blogId },
          { projection: { _id: 1 } }
        );
        if (!blogExists) {
          return res.status(404).json({
            success: false,
            message: "Blog not found",
          });
        }

        // Check for recent view from this IP (prevent refresh spam)
        const oneHourAgo = new Date(now - 3600000);
        const existingView = await blogsCollection.findOne(
          {
            _id: blogId,
            "viewDetails.ipAddress": ip,
            "viewDetails.viewedAt": { $gt: oneHourAgo },
          },
          { projection: { views: 1 } }
        );

        if (existingView) {
          return res.json({
            success: true,
            views: existingView.views,
            message: "View already recorded recently",
          });
        }

        // Atomic update with view tracking
        const updateResult = await blogsCollection.findOneAndUpdate(
          { _id: blogId },
          {
            $inc: { views: 1 },
            $push: {
              viewDetails: {
                viewedAt: now,
                userAgent,
                ipAddress: ip,
                referrer,
                sessionId: req.sessionID || null,
                // Additional useful fields:
                isMobile: /mobile/i.test(userAgent),
                browser: getBrowser(userAgent), // Implement this helper
                os: getOS(userAgent), // Implement this helper
              },
            },
          },
          {
            returnDocument: "after",
            projection: { views: 1 },
          }
        );

        res.json({
          success: true,
          views: updateResult.value.views,
          isNewView: true,
        });
      } catch (error) {
        console.error("View tracking error:", error);
        res.status(500).json({
          success: false,
          message: "Internal server error",
          error:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        });
      }
    });

    // Delete blog
    app.delete("/api/blogs/:id", verifyJWT, async (req, res) => {
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

    app.post("/api/blogs/:id/comments", verifyJWT, async (req, res) => {
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
          firebaseUid: authorId,
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
            authorId, // Store Firebase UID as string
            name: author.name,
            avatar: author.avatar,
          },
          likes: [], // This will store Firebase UIDs as strings
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
    app.patch("/api/comments/:id/like", verifyJWT, async (req, res) => {
      try {
        if (!ObjectId.isValid(req.params.id)) {
          return res.status(400).json({
            success: false,
            message: "Invalid comment ID format",
          });
        }

        const { authorId } = req.body; // This is Firebase UID (string)
        if (!authorId) {
          return res.status(400).json({
            success: false,
            message: "Author ID is required",
          });
        }

        const commentId = new ObjectId(req.params.id);

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

        // Find the comment
        const comment = blog.comments.find((c) => c._id.equals(commentId));
        const likeIndex = comment.likes.indexOf(authorId); // Compare strings

        let update;
        let isLiked;

        if (likeIndex === -1) {
          // Add like
          update = { $push: { "comments.$[elem].likes": authorId } };
          isLiked = true;
        } else {
          // Remove like
          update = { $pull: { "comments.$[elem].likes": authorId } };
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

        // Get updated comment
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
  } catch (err) {
    console.error("❌ DB connection error:", err);
  }
}
run();

// ====== Default Route ======
app.get("/", (req, res) => {
  res.send("🩸 Blood Donation App Server is Running");
});

module.exports = app;
