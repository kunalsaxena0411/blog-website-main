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
// If running locally for development, ensure this is set in your .env file or similar
const JWT_SECRET =
  process.env.JWT_SECRET ||
  "602c5dfb680d5789774a3fdbd2300d8756de317872a4c5f76e3df91a71e3342ea2b8959c289cd57fce1748ce53ec0aeb1939aa69c155de1384664f563ee702139"; // CHANGE THIS IN PRODUCTION!

// Define the email that will be allowed to register as an admin if no admin exists
const ALLOWED_ADMIN_EMAIL = "gamakauaa.com@gmail.com"; // Set this to your desired admin email

// Middleware
// Allows requests from your frontend origin (e.g., https://gamakauaa-frontend.onrender.com)
app.use(cors({
  origin: ["https://gamakauaa-frontend.onrender.com", "https://gamakauaa.com"], // ✅ Allow your frontend
  credentials: true // ✅ Allow cookies if needed
}));
// To parse JSON request bodies
app.use(express.json());

// MongoDB Connection String
// Replace 'nehaghure5:ig9CDghzNxt9SSpX' with your actual MongoDB Atlas username and password.
// For production, this should ideally be an environment variable (e.g., process.env.MONGODB_URI)
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

// Optional: Set strictQuery to false to suppress Mongoose 7+ warning.
// Be aware of the implications: queries with undefined/null paths might return all documents.
mongoose.set('strictQuery', false);

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
  imageUrl: { type: String, default: "" }, // New field for article image URL
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

// SavedArticle Schema - New Schema for "Save Post" functionality
const savedArticleSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  articleId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Article",
    required: true,
  },
  createdAt: { type: Date, default: Date.now },
});

// Ensure a user can only save an article once
savedArticleSchema.index({ userId: 1, articleId: 1 }, { unique: true });

const SavedArticle = mongoose.model("SavedArticle", savedArticleSchema);


// --- Nodemailer Transporter (for sending emails) ---
// IMPORTANT: Replace with your actual email service credentials.
// For testing, you can use a service like Ethereal.email (for development only) or Mailtrap.
// For production, use environment variables for security.
const transporter = nodemailer.createTransport({
  service: "gmail", // Example: Use Gmail. For production, consider dedicated services.
  auth: {
    user: "gamakauaa.com@gmail.com", // Your sending email address
    pass: "epkf gmxv potv acsw", // Replace with your Gmail App Password (NOT your regular password)
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
    // Specifically handle JsonWebTokenError for more specific client feedback
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: "Unauthorized: Token expired" });
    }
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
app.post("/api/auth/signup", async (req, res, next) => { // Added 'next' for error handling middleware
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

    // Send welcome email after successful signup
    const mailOptions = {
      from: "gamakauaa.com@gmail.com", // Sender address
      to: newUser.email, // Recipient address
      subject: "गामाकौआ में आपका स्वागत है!",
      html: `
        <p>प्रिय ${newUser.email},</p>
        <p>गामाकौआ समुदाय में आपका स्वागत है! हमें आपको अपने साथ पाकर खुशी हो रही है।</p>
        <p>अब आप हमारे सभी लेखों को एक्सप्लोर कर सकते हैं और हिंदी साहित्य और संस्कृति की दुनिया में गोता लगा सकते हैं।</p>
        <p>शुभ पठन!</p>
        <p>धन्यवाद,<br>गामाकौआ टीम</p>
      `,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Error sending welcome email after signup:", error);
      } else {
        console.log("Welcome Email sent on signup:", info.response);
      }
    });

    res.status(201).json({
      message: `Signed up successfully as ${role}. Please log in.`,
    });
  } catch (err) {
    console.error("Signup error:", err);
    next(err); // Pass error to global error handler
  }
});

// POST /api/auth/login - Authenticate a user
app.post("/api/auth/login", async (req, res, next) => { // Added 'next'
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

    // Send welcome email on login (if not sent before or as a reminder)
    const mailOptions = {
      from: "gamakauaa.com@gmail.com", // Sender address
      to: user.email, // Recipient address
      subject: "गामाकौआ में आपका स्वागत है!",
      html: `
        <p>प्रिय ${user.email},</p>
        <p>गामाकौआ में फिर से आपका स्वागत है! हमें खुशी है कि आप वापस आ गए हैं।</p>
        <p>हमारे नवीनतम लेखों और सामग्री का अन्वेषण करें।</p>
        <p>धन्यवाद,<br>गामाकौआ टीम</p>
      `,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Error sending welcome email after login:", error);
      } else {
        console.log("Welcome Email sent on login:", info.response);
      }
    });

    res.status(200).json({
      message: "Login successful.",
      token,
      user: { id: user._id, email: user.email, role: user.role },
    });
  } catch (error) {
    console.error("Login error:", error);
    next(error); // Pass error to global error handler
  }
});

// POST /api/auth/forgot-password - Request OTP for password reset
app.post("/api/auth/forgot-password", async (req, res, next) => { // Added 'next'
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ message: "Email is required." });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      // Return 200 OK even if user not found to prevent email enumeration
      // but log the actual status on the server side
      console.warn(`Forgot password attempt for unknown email: ${email}`);
      return res.status(200).json({ message: "यदि आपका ईमेल हमारे सिस्टम में है, तो आपको पासवर्ड रीसेट करने के लिए एक ओटीपी प्राप्त होगा।" });
    }

    // Generate 6-digit OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpires = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes

    user.otp = otp;
    user.otpExpires = otpExpires;
    await user.save();

    // Send OTP via email
    const mailOptions = {
      from: "gamakauaa.com@gmail.com", // Sender address
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
        // Do NOT return error status here, still send success to frontend to avoid user enumeration
        res.status(200).json({ message: "OTP generation successful, but failed to send email. Please try again later." });
      } else {
        console.log("OTP Email sent:", info.response);
        res.status(200).json({ message: "OTP sent to your email.", email: user.email });
      }
    });

  } catch (error) {
    console.error("Forgot password error:", error);
    next(error); // Pass error to global error handler
  }
});


// POST /api/auth/reset-password - Verify OTP and reset password
app.post("/api/auth/reset-password", async (req, res, next) => { // Added 'next'
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
    next(error); // Pass error to global error handler
  }
});


// --- Article Endpoints ---

// GET All Articles (Publicly accessible, with optional category filter)
app.get("/api/articles", async (req, res, next) => { // Added 'next'
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
    next(error); // Pass error to global error handler
  }
});

// GET Article by ID (Publicly accessible)
app.get("/api/articles/:id", async (req, res, next) => { // Added 'next'
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
    next(error); // Pass error to global error handler
  }
});

// POST New Article (Admin Only)
app.post("/api/articles", verifyToken, verifyAdmin, async (req, res, next) => { // Added 'next'
  // req.user contains the decoded JWT payload from verifyToken: { userId, email, role }
  const { title, category, content, imageUrl } = req.body; // 'author' will be taken from logged-in user's email

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
    imageUrl: imageUrl || "", // Save image URL, default to empty string if not provided
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
    next(error); // Pass error to global error handler
  }
});

// PUT/PATCH Update Article (Admin Only)
app.put("/api/articles/:id", verifyToken, verifyAdmin, async (req, res, next) => { // Added 'next'
  const { id } = req.params;
  const { title, category, content, imageUrl } = req.body; // Fields to update

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
    articleToUpdate.imageUrl =
      imageUrl !== undefined ? imageUrl : articleToUpdate.imageUrl; // Update image URL
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
    next(error); // Pass error to global error handler
  }
});

// DELETE Article (Admin Only)
app.delete("/api/articles/:id", verifyToken, verifyAdmin, async (req, res, next) => { // Added 'next'
  const { id } = req.params; // Get article ID from URL parameters

  try {
    const articleToDelete = await Article.findById(id);

    if (!articleToDelete) {
      return res.status(404).json({ message: "Article not found" });
    }

    // Optional: Add logic to ensure only the original author (if also admin) can delete their own post
    // if (articleToDelete.userId.toString() !== req.user.userId.toString()) {
    //     return res.status(403).json({ message: 'Forbidden: You can only delete your own articles.' });
    // }\

    // Also delete any saved entries for this article
    await SavedArticle.deleteMany({ articleId: id });


    await Article.findByIdAndDelete(id);
    res.status(200).json({ message: "Article deleted successfully!" });
  } catch (error) {
    console.error("Error deleting article:", error);
    // Handle invalid ID format
    if (error.name === "CastError") {
      return res.status(400).json({ message: "Invalid article ID format." });
    }
    next(error); // Pass error to global error handler
  }
});

// --- Saved Article Endpoints ---

// POST /api/users/:userId/saved-articles - Save an article for a specific user
app.post("/api/users/:userId/saved-articles", verifyToken, async (req, res, next) => { // Added 'next'
  const { userId } = req.params;
  const { articleId } = req.body; // articleId is now in the request body

  // Security check: Ensure the userId in the URL matches the authenticated user's ID
  if (req.user.userId.toString() !== userId.toString()) {
    return res.status(403).json({ message: "Forbidden: You can only save articles for your own user ID." });
  }

  try {
    // Check if article exists
    const article = await Article.findById(articleId);
    if (!article) {
      return res.status(404).json({ message: "Article not found." });
    }

    // Check if already saved by this user
    const existingSavedArticle = await SavedArticle.findOne({ userId, articleId });
    if (existingSavedArticle) {
      return res.status(409).json({ message: "Article already saved by this user." });
    }

    const newSavedArticle = new SavedArticle({ userId, articleId });
    await newSavedArticle.save();

    res.status(201).json({ message: "Article saved successfully!" });
  } catch (error) {
    console.error("Error saving article:", error);
    if (error.name === "CastError") {
      return res.status(400).json({ message: "Invalid article ID format." });
    }
    next(error); // Pass error to global error handler
  }
});

// GET /api/users/:userId/saved-articles - Get all saved articles for a specific user
app.get("/api/users/:userId/saved-articles", verifyToken, async (req, res, next) => { // Added 'next'
  const { userId } = req.params;

  // Security check: Ensure the userId in the URL matches the authenticated user's ID
  if (req.user.userId.toString() !== userId.toString()) {
    return res.status(403).json({ message: "Forbidden: You can only view your own saved articles." });
  }

  try {
    const savedArticles = await SavedArticle.find({ userId })
      .select('articleId') // Select only the articleId field
      .lean(); // Return plain JavaScript objects

    // We only need the IDs on the frontend to check if an article is saved.
    // The frontend will then fetch full article details as needed.
    const savedArticleIds = savedArticles.map(sa => sa.articleId.toString());

    res.status(200).json({ savedArticles: savedArticleIds });
  } catch (error) {
    console.error("Error fetching saved articles:", error);
    next(error); // Pass error to global error handler
  }
});


// DELETE /api/users/:userId/saved-articles/:articleId - Unsave an article for a specific user
app.delete("/api/users/:userId/saved-articles/:articleId", verifyToken, async (req, res, next) => { // Added 'next'
  const { userId, articleId } = req.params;

  // Security check: Ensure the userId in the URL matches the authenticated user's ID
  if (req.user.userId.toString() !== userId.toString()) {
    return res.status(403).json({ message: "Forbidden: You can only unsave articles for your own user ID." });
  }

  try {
    const result = await SavedArticle.deleteOne({ userId, articleId });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Saved article not found for this user." });
    }

    res.status(200).json({ message: "Article unsaved successfully!" });
  } catch (error) {
    console.error("Error unsaving article:", error);
    if (error.name === "CastError") {
      return res.status(400).json({ message: "Invalid article ID format." });
    }
    next(error); // Pass error to global error handler
  }
});

// POST /api/contact - Handle contact form submissions
app.post("/api/contact", async (req, res, next) => {
  const { name, email, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({ message: "Name, email, and message are required." });
  }

  try {
    // Email recipient for contact form
    const contactRecipientEmail = "gamakauaa.com@gmail.com"; // Set to your actual contact email

    const mailOptions = {
      from: email, // Sender will be the user's email from the form
      to: contactRecipientEmail,
      subject: `गामाकौआ संपर्क फ़ॉर्म से नया संदेश: ${name}`,
      html: `
        <p><b>प्रेषक का नाम:</b> ${name}</p>
        <p><b>प्रेषक का ईमेल:</b> ${email}</p>
        <p><b>संदेश:</b></p>
        <p>${message}</p>
      `,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Error sending contact form email:", error);
        // Important: Still return success to frontend to avoid revealing server-side email issues
        return res.status(500).json({ message: "संदेश भेजने में त्रुटि हुई, कृपया बाद में पुनः प्रयास करें।" });
      }
      console.log("Contact form email sent:", info.response);
      res.status(200).json({ message: "आपका संदेश सफलतापूर्वक भेजा गया है। गामाकौआ टीम आपसे जल्द ही संपर्क करेगी।" });
    });
  } catch (error) {
    console.error("Contact form submission handler error:", error);
    next(error); // Pass error to global error handler
  }
});


// --- Global Error Handling Middleware ---
// This middleware will catch any errors passed to `next(error)` from your routes.
// It ensures that all errors return a consistent JSON response instead of default HTML error pages.
app.use((err, req, res, next) => {
  console.error("Global Error Handler:", err.stack); // Log the full stack trace for debugging

  // Default error message and status
  let statusCode = err.statusCode || 500;
  let message = err.message || "An unexpected server error occurred.";

  // Specific error handling for Mongoose validation errors
  if (err.name === 'ValidationError') {
    statusCode = 400; // Bad request
    message = err.message; // Mongoose validation messages are usually descriptive
  } else if (err.name === 'CastError' && err.kind === 'ObjectId') {
    statusCode = 400; // Bad request for invalid ID format
    message = `Invalid ID format for ${err.path}: ${err.value}`;
  } else if (err.code === 11000) { // MongoDB duplicate key error (e.g., unique email constraint)
    statusCode = 409; // Conflict
    message = "Duplicate key error: This resource already exists.";
    if (err.keyValue && Object.keys(err.keyValue).length > 0) {
        message = `Duplicate entry for ${Object.keys(err.keyValue)[0]}: ${Object.values(err.keyValue)[0]} already exists.`;
    }
  }

  // Send the error response as JSON
  res.status(statusCode).json({
    message: message,
    // In development, you might send more error details. In production, be less verbose.
    // error: process.env.NODE_ENV === 'production' ? {} : { name: err.name, details: err.message, stack: err.stack }
  });
});

// Catch-all for 404 Not Found (must be after all other routes)
app.use((req, res, next) => {
  res.status(404).json({ message: "API endpoint not found." });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
