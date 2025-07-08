require("dotenv").config();
const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
const nodemailer = require("nodemailer");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");

const app = express();
const port = process.env.PORT || 5000;

// ====== Middleware Setup ======
const corsOptions = {
  origin: "http://localhost:5173",
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

let usersCollection;
let donationRequestCollection;

async function run() {
  try {
    await client.connect();
    const db = client.db("bloodDonationApp");
    usersCollection = db.collection("users");
    donationRequestCollection = db.collection("donationRequest");

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

    // ====== ADMIN: User Management ======
    app.get("/api/users", verifyJWT, verifyAdmin, async (req, res) => {
      const users = await usersCollection.find().toArray();
      res.json(users);
    });

    app.post("/api/users", async (req, res) => {
      const user = req.body;
      const result = await usersCollection.insertOne(user);
      res.json({ success: result.acknowledged === 1 });
    });

    app.patch(
      "/api/users/status/:id",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        const { status } = req.body;
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { status } }
        );
        res.json({ success: result.modifiedCount === 1 });
      }
    );

    app.patch(
      "/api/users/role/:id",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        const { role } = req.body;
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { role } }
        );
        res.json({ success: result.modifiedCount === 1 });
      }
    );

    app.delete("/api/users/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const result = await usersCollection.deleteOne({
        _id: new ObjectId(req.params.id),
      });
      res.json({ success: result.deletedCount === 1 });
    });

    // ====== ADMIN: Donation Request Management ======
    app.get(
      "/api/donation-requests",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        const requests = await donationRequestCollection.find().toArray();
        res.json(requests);
      }
    );

    app.patch(
      "/api/donation-requests/status/:id",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        const { status } = req.body;
        const result = await donationRequestCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { status } }
        );
        res.json({ success: result.modifiedCount === 1 });
      }
    );

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
