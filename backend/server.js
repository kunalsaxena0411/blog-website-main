const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs"); // For password hashing
const jwt = require("jsonwebtoken"); // For user authentication tokens
const nodemailer = require("nodemailer"); // For sending emails (OTP)
const crypto = require("crypto"); // For generating OTPs

const app = express();
const PORT = process.env.PORT || 3000;
// It's crucial to set JWT_SECRET in environment variables in production
const JWT_SECRET =
  process.env.JWT_SECRET ||
  "602c5dfb680d578974a3fdbd2300d8756de317872a4c5f76e3df91a71e3342ea2b8959c289cd57fce1748ce53ec0aeb1939aa69c155de1384664f563ee702139"; // CHANGE THIS IN PRODUCTION!

// Define the email that will be allowed to register as an admin if no admin exists
const ALLOWED_ADMIN_EMAIL = "gamakauaa.com@gmail.com"; // Set this to your desired admin email

// Middleware
// Allows requests from your frontend origin (e.g., http://localhost:5500 if using Live Server)
app.use(cors());
// To parse JSON request bodies
app.use(express.json());

// MongoDB Connection String
// Replace 'nehaghure5:ig9CDghzNxt9SSpX' with your actual MongoDB Atlas username and password.
const MONGODB_URI =
  "mongodb+srv://nehaghure5:ig9CDghzNxt9SSpX@cluster0.grixzsn.mongodb.net/gamakauaaDB?retryWrites=true&w=majority&appName=Cluster0";

// Connect to MongoDB
mongoose
  .connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("MongoDB connected successfully");
  })
  .catch((err) => console.error("MongoDB connection error:", err));

// --- Mongoose Schemas and Models ---

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true }, // 'email' is now the unique field
  password: { type: String, required: true }, // Hashed password
  role: { type: String, default: "user" }, // 'user' or 'admin'
  otp: { type: String }, // For password reset OTP
  otpExpires: { type: Date }, // Expiry for OTP
  createdAt: { type: Date, default: Date.now },
});

// Pre-save hook to hash password before saving
userSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

const User = mongoose.model("User", userSchema);

// Article Schema
const articleSchema = new mongoose.Schema({
  title: { type: String, required: true },
  author: { type: String, required: true }, // This will be the email of the user who posted
  category: { type: String, required: true }, // Category for the article
  content: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }, // MongoDB User _id reference
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// Pre-save hook to update 'updatedAt' timestamp
articleSchema.pre("save", function (next) {
  this.updatedAt = new Date();
  next();
});

const Article = mongoose.model("Article", articleSchema);

// --- Nodemailer Transporter (for sending emails) ---
// IMPORTANT: Replace with your actual email service credentials.
// For testing, you can use a service like Ethereal.email (for development only) or Mailtrap.
// For production, use environment variables for security.
const transporter = nodemailer.createTransport({
  service: "gmail", // Example: Use Gmail. For production, consider dedicated services.
  auth: {
    user: "nirzara.antiai@gmail.com", // Replace with your Gmail address
    pass: "qhxt wsuv hunf swrl", // Replace with your Gmail App Password (NOT your regular password)
  },
});

// --- Middleware for JWT Verification ---
// Verifies the JWT from the Authorization header and attaches user data to req.user
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }

  const token = authHeader.split("Bearer ")[1];
  if (!token) {
    return res.status(401).json({ message: "Unauthorized: Token malformed" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // Payload: { userId, email, role }
    next();
  } catch (error) {
    console.error("JWT Verification Error:", error.message);
    return res.status(401).json({ message: "Unauthorized: Invalid token" });
  }
};

// --- Middleware for Admin Role Check ---
// Ensures the authenticated user has an 'admin' role
const verifyAdmin = (req, res, next) => {
  // This middleware assumes verifyToken has already run and attached req.user
  if (!req.user || req.user.role !== "admin") {
    return res
      .status(403)
      .json({ message: "Forbidden: Admin access required" });
  }
  next();
};

// --- Authentication Endpoints ---

// POST /api/auth/signup - Register a new user
app.post("/api/auth/signup", async (req, res) => {
  let { email = "", password } = req.body;
  email = email.toLowerCase().trim(); // always normalise email

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password required." });
  }

  try {
    // Check if user already exists
    if (await User.findOne({ email })) {
      return res.status(409).json({ message: "User already exists." });
    }

    // Determine role: The very first user with ALLOWED_ADMIN_EMAIL can be an admin.
    // Otherwise, all signups are 'user' roles.
    let role = "user";
    const adminExists = await User.exists({ role: "admin" });
    if (!adminExists && email === ALLOWED_ADMIN_EMAIL) {
      role = "admin";
    } else if (email === ALLOWED_ADMIN_EMAIL && adminExists) {
      // If admin email is used but an admin already exists, deny admin signup for this email
      return res.status(403).json({ message: "Admin user already exists. Cannot register another admin with this email." });
    }

    const newUser = await User.create({ email, password, role });
    res.status(201).json({
      message: `Signed up successfully as ${role}. Please log in.`,
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ message: "Server error during signup." });
  }
});

// POST /api/auth/login - Authenticate a user
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res
      .status(400)
      .json({ message: "Email and password are required." });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    // Generate JWT with user's MongoDB _id, email, and role
    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "365d" } // Token expires in 365 days
    );

    res.status(200).json({
      message: "Login successful.",
      token,
      user: { id: user._id, email: user.email, role: user.role },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      message: "Server error during login. Please try again later.",
      details: error.message,
    });
  }
});

// POST /api/auth/forgot-password - Request OTP for password reset
app.post("/api/auth/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ message: "Email is required." });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found with this email." });
    }

    // Generate 6-digit OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpires = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes

    user.otp = otp;
    user.otpExpires = otpExpires;
    await user.save();

    // Send OTP via email (replace with actual email sending logic)
    const mailOptions = {
      from: "nirzara.antiai@gmail.com", // Sender address
      to: user.email, // Recipient address
      subject: "गामाकौआ: पासवर्ड रीसेट ओटीपी",
      html: `
        <p>प्रिय ${user.email},</p>
        <p>आपके पासवर्ड को रीसेट करने के लिए आपका वन-टाइम पासवर्ड (OTP) है: <strong>${otp}</strong></p>
        <p>यह ओटीपी 10 मिनट में समाप्त हो जाएगा।</p>
        <p>यदि आपने इस अनुरोध को नहीं किया है, तो कृपया इस ईमेल को अनदेखा करें।</p>
        <p>धन्यवाद,<br>गामाकौआ टीम</p>
      `,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Error sending OTP email:", error);
        // Even if email fails, return success to prevent email enumeration
        return res.status(500).json({ message: "OTP generation successful, but failed to send email. Please try again later." });
      }
      console.log("OTP Email sent:", info.response);
      res.status(200).json({ message: "OTP sent to your email.", email: user.email });
    });

  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({ message: "Server error during forgot password request." });
  }
});


// POST /api/auth/reset-password - Verify OTP and reset password
app.post("/api/auth/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword) {
    return res.status(400).json({ message: "Email, OTP, and new password are required." });
  }

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Check if OTP matches and is not expired
    if (user.otp !== otp || user.otpExpires < Date.now()) {
      return res.status(400).json({ message: "Invalid or expired OTP." });
    }

    // Update password and clear OTP fields
    user.password = newPassword; // Pre-save hook will hash it
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    res.status(200).json({ message: "Password reset successfully. You can now log in with your new password." });

  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({ message: "Server error during password reset." });
  }
});


// --- Article Endpoints ---

// GET All Articles (Publicly accessible, with optional category filter)
app.get("/api/articles", async (req, res) => {
  try {
    const { category } = req.query; // Get category from query parameters

    let query = {};
    if (category) {
      query.category = category; // Add category filter to query
    }

    const articles = await Article.find(query).sort({ createdAt: -1 }); // Sort by newest first
    res.status(200).json(articles);
  } catch (error) {
    console.error("Error fetching articles:", error);
    res
      .status(500)
      .json({ message: "Error fetching articles", error: error.message });
  }
});

// GET Article by ID (Publicly accessible)
app.get("/api/articles/:id", async (req, res) => {
  try {
    const article = await Article.findById(req.params.id);
    if (!article) {
      return res.status(404).json({ message: "Article not found." });
    }
    res.status(200).json(article);
  } catch (error) {
    console.error("Error fetching article by ID:", error);
    // CastError happens if ID format is invalid
    if (error.name === "CastError") {
      return res.status(400).json({ message: "Invalid article ID format." });
    }
    res.status(500).json({
      message: "Server error fetching article.",
      error: error.message,
    });
  }
});

// POST New Article (Admin Only)
app.post("/api/articles", verifyToken, verifyAdmin, async (req, res) => {
  // req.user contains the decoded JWT payload from verifyToken: { userId, email, role }
  const { title, category, content } = req.body; // 'author' will be taken from logged-in user's email

  // Ensure all required fields are present
  if (!title || !category || !content) {
    return res
      .status(400)
      .json({ message: "All article fields (title, category, content) are required." });
  }

  const newArticle = new Article({
    title,
    author: req.user.email, // Use email from decoded JWT as author
    category,
    content,
    userId: req.user.userId, // Use MongoDB user ID from decoded JWT
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  try {
    const savedArticle = await newArticle.save();
    res
      .status(201)
      .json({ message: "Article posted successfully!", article: savedArticle });
  } catch (error) {
    console.error("Error posting article:", error);
    res
      .status(400)
      .json({ message: "Error posting article", error: error.message });
  }
});

// PUT/PATCH Update Article (Admin Only)
app.put("/api/articles/:id", verifyToken, verifyAdmin, async (req, res) => {
  const { id } = req.params;
  const { title, category, content } = req.body; // Fields to update

  try {
    const articleToUpdate = await Article.findById(id);

    if (!articleToUpdate) {
      return res.status(404).json({ message: "Article not found" });
    }

    // Optional: Add logic to ensure only the original author (if also admin) can update their own post
    // if (articleToUpdate.userId.toString() !== req.user.userId.toString()) {
    //     return res.status(403).json({ message: 'Forbidden: You can only update your own articles.' });
    // }

    // Update fields if provided in the request body, otherwise keep existing
    articleToUpdate.title = title !== undefined ? title : articleToUpdate.title;
    // author is not updatable via this endpoint, it's tied to the user who posted it
    articleToUpdate.category =
      category !== undefined ? category : articleToUpdate.category;
    articleToUpdate.content =
      content !== undefined ? content : articleToUpdate.content;
    articleToUpdate.updatedAt = new Date(); // Update timestamp

    const updatedArticle = await articleToUpdate.save();
    res.status(200).json({
      message: "Article updated successfully!",
      article: updatedArticle,
    });
  } catch (error) {
    console.error("Error updating article:", error);
    // Handle invalid ID format
    if (error.name === "CastError") {
      return res.status(400).json({ message: "Invalid article ID format." });
    }
    res
      .status(500)
      .json({ message: "Error updating article", error: error.message });
  }
});

// DELETE Article (Admin Only)
app.delete("/api/articles/:id", verifyToken, verifyAdmin, async (req, res) => {
  const { id } = req.params; // Get article ID from URL parameters

  try {
    const articleToDelete = await Article.findById(id);

    if (!articleToDelete) {
      return res.status(404).json({ message: "Article not found" });
    }

    // Optional: Add logic to ensure only the original author (if also admin) can delete their own post
    // if (articleToDelete.userId.toString() !== req.user.userId.toString()) {
    //     return res.status(403).json({ message: 'Forbidden: You can only delete your own articles.' });
    // }

    await Article.findByIdAndDelete(id);
    res.status(200).json({ message: "Article deleted successfully!" });
  } catch (error) {
    console.error("Error deleting article:", error);
    // Handle invalid ID format
    if (error.name === "CastError") {
      return res.status(400).json({ message: "Invalid article ID format." });
    }
    res
      .status(500)
      .json({ message: "Error deleting article", error: error.message });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});