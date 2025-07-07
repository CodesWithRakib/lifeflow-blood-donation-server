const express = require("express");
const { MongoClient, ServerApiVersion } = require("mongodb");
const app = express();
const cors = require("cors");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const port = process.env.PORT || 5000;

const corsOptions = {
  origin: "http://localhost:3000",
  credentials: true, //access-control-allow-credentials:true
  optionSuccessStatus: 200,
};

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());
// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(process.env.DB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// ========== JWT Middleware ==========
const verifyJWT = (req, res, next) => {
  const token = req?.cookies.jwt;

  if (!token)
    return res
      .status(401)
      .json({ success: false, message: "Unauthorized access" });

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, decoded) => {
    if (error)
      return res
        .status(403)
        .json({ success: false, message: "Forbidden access" });

    req.email = decoded.email;
    next();
  });
};

// ========== Run Application ==========
async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const db = client.db("bloodDonationApp");
    const usersCollection = db.collection("users");
    const donationCollection = db.collection("donation");
    const donationHistoryCollection = db.collection("donationHistory");
    const donationRequestCollection = db.collection("donationRequest");
    const bloodCollection = db.collection("blood");
    const bloodDonationCollection = db.collection("bloodDonation");

    // ---------- Auth ----------
    app.post("/jwt", (req, res) => {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ message: "Email is required" });
      }

      const token = jwt.sign({ email }, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "7d",
      });

      res
        .cookie("jwt", token, cookieOptions)
        .json({ message: "JWT cookie set successfully" });
    });

    app.post("/logout", (req, res) => {
      res.clearCookie("jwt", cookieOptions);
      res.send({ message: "jwt cleared successfully" });
    });
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Blood Donation App Server is Running");
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
