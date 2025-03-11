const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config();
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const SECRET_KEY = "your_secret_key"; // Change this to a strong secret

// MongoDB connection
mongoose.connect(process.env.MONGO, {});
// User schema and model
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  fcmToken: String, // Store FCM token
});

const User = mongoose.model("User", userSchema);

// Vehicle schema and model
const vehicleSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'  // Reference to User model
  },
  type: String,
  model: String,
  registrationNo: String,
});
const Vehicle = mongoose.model("Vehicle", vehicleSchema);

// FuelOrder schema and model
const fuelOrderSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'  // Reference to User model
  },
  vehicleId: { 
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Vehicle'  // Reference to Vehicle model
  },
  date: { type: Date, default: Date.now },
  status: { type: String, default: "Pending" },
  fuelType: String,
  amount: Number,
});
const FuelOrder = mongoose.model("FuelOrder", fuelOrderSchema);
app.use(express.json());
app.use(cors());

// Middleware to authenticate JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Access denied" });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
};
app.get("/status",(req,res)=>res.json("OK"))
// Register route
app.post("/register", async (req, res) => {
  try {
    const { username, password, fcmToken } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, fcmToken });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ error: "Error registering user" });
  }
});


// Login route
app.post("/login", async (req, res) => {
  try {
    const { username, password, fcmToken } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    // Update FCM Token on login
    user.fcmToken = fcmToken;
    await user.save();

    const token = jwt.sign({ userId: user._id }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: "Error logging in" });
  }
});

// Add a vehicle
app.post("/vehicles", authenticateToken, async (req, res) => {
  try {
    const { type, model, registrationNo } = req.body;
    const newVehicle = new Vehicle({
      userId: req.user.userId,
      type,
      model,
      registrationNo,
    });
    await newVehicle.save();
    res.status(201).json({ message: "Vehicle added successfully", vehicle: newVehicle });
  } catch (error) {
    res.status(500).json({ error: "Error adding vehicle" });
  }
});

// Get all vehicles for a user
app.get("/vehicles", authenticateToken, async (req, res) => {
  try {
    const vehicles = await Vehicle.find({ userId: req.user.userId });
    res.json(vehicles);
  } catch (error) {
    res.status(500).json({ error: "Error fetching vehicles" });
  }
});



// Create a fuel order
app.post("/orders", authenticateToken, async (req, res) => {
  try {
    const { vehicleId, fuelType, amount } = req.body;

    const existingOrder = await FuelOrder.findOne({ 
      vehicleId, 
      status: "Pending" 
    });

    if (existingOrder) {
      return res.status(400).json({ error: "A pending order already exists for this vehicle." });
    }

    const newOrder = new FuelOrder({
      userId: req.user.userId,
      vehicleId,
      fuelType,
      amount,
    });

    await newOrder.save();
    res.status(201).json({ message: "Order created successfully", order: newOrder });
  } catch (error) {
    res.status(500).json({ error: "Error creating order" });
  }
});
app.post("/update-fcm-token", authenticateToken, async (req, res) => {
  try {
    const { fcmToken } = req.body;
    await User.updateOne({ _id: req.user.userId }, { fcmToken });
    res.json({ message: "FCM token updated successfully" });
  } catch (error) {
    res.status(500).json({ error: "Error updating FCM token" });
  }
});

// Get all orders for a user
app.get("/orders", authenticateToken, async (req, res) => {
  try {
    // Fetch orders and populate vehicleId with 'registrationNo' (vehicleNumber)
    const orders = await FuelOrder.find({ userId: req.user.userId }).lean()
      .populate({
        path: "vehicleId", // Populating vehicleId
        select: "registrationNo" // Selecting the 'registrationNo' (vehicleNumber) field
      });
    
    // Map over the orders to include vehicleNumber directly in the response
    const ordersWithVehicleNumber = orders.map(order => {
      return {
        ...order,
        vehicleNumber: order.vehicleId ? order.vehicleId.registrationNo : null
      };
    });
    
    console.log(ordersWithVehicleNumber);
    // Respond with the orders including vehicleNumber
    res.json(ordersWithVehicleNumber);
  } catch (error) {
    res.status(500).json({ error: "Error fetching orders" });
  }
});


// WebSocket connection for ESP32
const userSockets = new Map();
const admin = require("firebase-admin");

// Initialize Firebase Admin SDK
const serviceAccount = require("./firebase-adminsdk.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// WebSocket server logic
wss.on("connection", (ws, req) => {
  console.log("Client connected");

  ws.on("message", async (message) => {
    try {
      const data = JSON.parse(message);
      console.log(data);

      if (data.type === "register") {
        userSockets.set(data.userId, ws);
        console.log(`User ${data.userId} registered for WebSocket updates.`);
      }

      if (data.type === "vehicle_entry") {
        const vehicleNumber = data.vehicleNumber;
        console.log(`Vehicle arrived: ${vehicleNumber}`);

        const vehicle = await Vehicle.findOne({ registrationNo: vehicleNumber });
        if (!vehicle) {
          console.log(`Vehicle ${vehicleNumber} not found in database.`);
          return;
        }

        const pendingOrder = await FuelOrder.findOne({
          vehicleId: vehicle._id,
          status: "Pending",
        }).populate("vehicleId");

        if (pendingOrder) {
          console.log(`Pending order found for ${vehicleNumber}, notifying user...`);

          const userSocket = userSockets.get(pendingOrder.userId.toString());
          if (userSocket && userSocket.readyState === WebSocket.OPEN) {
            userSocket.send(
              JSON.stringify({
                type: "confirm_fuel_dispensing",
                order: {
                  id: pendingOrder._id,
                  vehicleNumber: pendingOrder.vehicleId.registrationNo,
                  fuelType: pendingOrder.fuelType,
                  amount: pendingOrder.amount,
                },
              })
            );
            console.log(`Alert sent to user ${pendingOrder.userId} for confirmation.`);

            // Send Push Notification to User
            await sendPushNotification(pendingOrder.userId, pendingOrder);
          } else {
            console.log(`User ${pendingOrder.userId} is not connected via WebSocket.`);
            await sendPushNotification(pendingOrder.userId, pendingOrder);
          }
        } else {
          console.log(`No pending order found for ${vehicleNumber}.`);
        }
      }

      if (data.type === "confirm_dispensing") {
        const { orderId, confirm } = data;
        
        if (confirm) {
          await FuelOrder.updateOne({ _id: orderId }, { status: "Confirmed" });
          console.log(`Order ${orderId} confirmed for dispensing.`);
          
          // Get the order details to send to ESP32
          const order = await FuelOrder.findById(orderId);
          
          // Send dispense command to the specific ESP32
          if (order && clients[order.deviceId]) {
            const dispenseCommand = {
              type: "dispense_fuel",
              amount: order.fuelAmount,
              orderId: orderId
            };
            
            clients[order.deviceId].send(JSON.stringify(dispenseCommand));
            console.log(`Fuel dispensing command sent to device ${order.deviceId} for order ${orderId}`);
          } else {
            console.log(`Cannot send dispensing command: Device ${order?.deviceId || 'unknown'} not connected`);
          }
        } else {
          await FuelOrder.updateOne({ _id: orderId }, { status: "Rejected" });
          console.log(`Order ${orderId} not confirmed.`);
        }
      }
    } catch (error) {
      console.error("Error processing WebSocket message:", error);
    }
  });

  ws.on("close", () => {
    console.log("Client disconnected");

    for (const [userId, socket] of userSockets.entries()) {
      if (socket === ws) {
        userSockets.delete(userId);
        break;
      }
    }
  });
});

// Send Push Notification to User
async function sendPushNotification(userId, order) {
  try {
    // Fetch the user's FCM token from the database (Assuming you store it in the User model)
    const user = await User.findById(userId);
    if (!user || !user.fcmToken) {
      console.log("FCM Token not found for user:", userId);
      return;
    }

    const message = {
      notification: {
        title: "Fuel Dispensing Confirmation",
        body: `Your fuel order (${order.fuelType}, ${order.amount}L) is ready for dispensing.`,
      },
      token: user.fcmToken,
    };

    // Send the message via FCM
    await admin.messaging().send(message);
    console.log(`Push notification sent to user ${userId}`);
  } catch (error) {
    console.error("Error sending push notification:", error);
  }
}


// Start the server
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
