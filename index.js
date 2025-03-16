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
const cookieParser = require("cookie-parser");
app.use(cookieParser())
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
function authenticateAdmin(req, res, next) {
  const token = req.cookies.adminToken; // Get token from cookies

  if (!token) {
      return res.status(401).json({ message: "Access Denied: No Token Provided" });
  }

  try {
      const verified = jwt.verify(token, SECRET_KEY); // Ensure JWT_SECRET is set in .env
      
      if (verified.admin !== "admin") {
          return res.status(403).json({ message: "Access Denied: Not an Admin" });
      }
      req.admin = verified;
      next();
  } catch (err) {
      res.status(400).json({ message: "Invalid Token" });
  }
};
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
  deviceId: String, // Add deviceId to track which device should dispense fuel
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
    const { vehicleId, fuelType, amount, deviceId } = req.body;

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
      deviceId: deviceId || "esp32_fuel_dispenser_01", // Default device ID if not provided
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

// WebSocket connection handling
const userSockets = new Map(); // Map userId -> WebSocket
const deviceSockets = new Map(); // Map deviceId -> WebSocket
const adminSockets = new Map();
// Initialize Firebase Admin SDK
const admin = require("firebase-admin");
const serviceAccount = require("./firebase-adminsdk.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
function broadcastToAdmins(message) {
  for (const [adminId, socket] of adminSockets.entries()) {
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify(message));
    }
  }
}
// WebSocket server logic
wss.on("connection", (ws, req) => {
  console.log("New client connected");
  
  ws.on("message", async (message) => {
    try {
      
      broadcastToAdmins(message)
      const data = JSON.parse(message);
      console.log("Received message:", data);

      // User registration in WebSocket
      if (data.type === "register") {
        userSockets.set(data.userId, ws);
        console.log(`User ${data.userId} registered for WebSocket updates.`);
      }
      if (data.type === "admin_register") {
        adminSockets.set(data.adminId, ws);
        console.log(`Admin ${data.adminId} registered for WebSocket updates.`);
      }

      // Device registration in WebSocket
      if (data.type === "device_register") {
        const deviceId = data.deviceId;
        deviceSockets.set(deviceId, ws);
        console.log(`Device ${deviceId} registered.`);
        
        // Send acknowledgment back to device
        ws.send(JSON.stringify({
          type: "register_ack",
          deviceId: deviceId,
          status: "success"
        }));
      }

      // Vehicle detection from RFID reader
      if (data.type === "vehicle_entry") {
        const vehicleNumber = data.vehicleNumber;
        const deviceId = data.deviceId;
        
        console.log(`Vehicle detected: ${vehicleNumber} at device: ${deviceId}`);

        // Find vehicle in database
        const vehicle = await Vehicle.findOne({ registrationNo: vehicleNumber });
        if (!vehicle) {
          console.log(`Vehicle ${vehicleNumber} not found in database.`);
          return;
        }

        // Find pending order for this vehicle
        const pendingOrder = await FuelOrder.findOne({
          vehicleId: vehicle._id,
          status: "Pending",
        }).populate("vehicleId userId");

        if (pendingOrder) {
          console.log(`Pending order found for ${vehicleNumber}, notifying user...`);
          
          // Update the order with the device that detected the vehicle
          await FuelOrder.updateOne(
            { _id: pendingOrder._id },
            { deviceId: deviceId }
          );

          // Notify user via WebSocket if connected
          const userSocket = userSockets.get(pendingOrder.userId._id.toString());
          if (userSocket && userSocket.readyState === WebSocket.OPEN) {
            userSocket.send(
              JSON.stringify({
                type: "confirm_fuel_dispensing",
                order: {
                  id: pendingOrder._id,
                  vehicleNumber: pendingOrder.vehicleId.registrationNo,
                  fuelType: pendingOrder.fuelType,
                  amount: pendingOrder.amount,
                  deviceId: deviceId
                },
              })
            );
            console.log(`Alert sent to user ${pendingOrder.userId._id} for confirmation.`);
          } else {
            console.log(`User ${pendingOrder.userId._id} is not connected via WebSocket.`);
          }
          
          // Always send push notification
          await sendPushNotification(pendingOrder.userId._id, pendingOrder);
        } else {
          console.log(`No pending order found for ${vehicleNumber}.`);
        }
      }

      // User confirms fuel dispensing
      if (data.type === "confirm_dispensing") {
        const { orderId, confirm } = data;
        
        if (confirm) {
          // Get order details
          const order = await FuelOrder.findById(orderId);
          if (!order) {
            console.log(`Order ${orderId} not found.`);
            return;
          }
          
          // Update order status
          await FuelOrder.updateOne({ _id: orderId }, { status: "Dispensing" });
          console.log(`Order ${orderId} confirmed for dispensing.`);
          
          // Get the device WebSocket connection
          const deviceSocket = deviceSockets.get(order.deviceId);
          if (deviceSocket && deviceSocket.readyState === WebSocket.OPEN) {
            // Send dispense command to the ESP32 device
            const dispenseCommand = {
              type: "dispense_fuel",
              amount: order.amount,
              orderId: orderId.toString()
            };
            
            deviceSocket.send(JSON.stringify(dispenseCommand));
            console.log(`Fuel dispensing command sent to device ${order.deviceId} for order ${orderId}`);
          } else {
            console.log(`Cannot send dispensing command: Device ${order.deviceId} not connected`);
          }
        } else {
          await FuelOrder.updateOne({ _id: orderId }, { status: "Rejected" });
          console.log(`Order ${orderId} rejected.`);
        }
      }

      // Handle dispense acknowledgment
      if (data.type === "dispense_acknowledge") {
        const { orderId, deviceId, status } = data;
        console.log(`Dispensing acknowledgment received from ${deviceId} for order ${orderId}: ${status}`);
      }

      // Handle dispensing status updates
      if (data.type === "dispense_status") {
        const { litres, deviceId, orderId } = data;
        console.log(`Dispensing status: ${litres} litres dispensed for order ${orderId}`);
        
        // Find the order
        const order = await FuelOrder.findById(orderId);
        if (order) {
          // Find user socket to send updates
          const userSocket = userSockets.get(order.userId.toString());
          if (userSocket && userSocket.readyState === WebSocket.OPEN) {
            userSocket.send(JSON.stringify({
              type: "dispensing_progress",
              orderId: orderId,
              litres: litres,
              total: order.amount
            }));
          }
        }
      }

      // Handle dispensing complete
      if (data.type === "dispense_complete") {
        const { totalLitres, deviceId, orderId } = data;
        console.log(`Dispensing complete: ${totalLitres} litres for order ${orderId}`);
        
        // Update order status in database
        await FuelOrder.updateOne(
          { _id: orderId },
          { 
            status: "Completed",
            amount: totalLitres // Update with actual amount dispensed
          }
        );
        
        // Find the order to get user info
        const order = await FuelOrder.findById(orderId).populate("userId");
        if (order) {
          // Notify user via WebSocket if connected
          const userSocket = userSockets.get(order.userId._id.toString());
          if (userSocket && userSocket.readyState === WebSocket.OPEN) {
            userSocket.send(JSON.stringify({
              type: "dispensing_complete",
              orderId: orderId,
              totalLitres: totalLitres
            }));
          }
          
          // Send push notification
          await sendPushNotification(order.userId._id, {
            _id: orderId,
            fuelType: order.fuelType,
            amount: totalLitres,
            status: "Completed"
          }, true);
        }
      }

      // Handle pong response from device
      if (data.type === "pong") {
        console.log(`Received pong from device ${data.deviceId}, status: ${data.status}`);
      }
    } catch (error) {
      console.error("Error processing WebSocket message:", error);
    }
  });

  ws.on("close", () => {
    console.log("Client disconnected");

    // Remove from user sockets if it was a user
    for (const [userId, socket] of userSockets.entries()) {
      if (socket === ws) {
        userSockets.delete(userId);
        console.log(`User ${userId} disconnected`);
        break;
      }
    }
    for (const [adminId, socket] of adminSockets.entries()) {
      if (socket === ws) {
        adminSockets.delete(adminId);
        console.log(`Admin ${adminId} disconnected`);
        break;
      }
    }
    // Remove from device sockets if it was a device
    for (const [deviceId, socket] of deviceSockets.entries()) {
      if (socket === ws) {
        deviceSockets.delete(deviceId);
        console.log(`Device ${deviceId} disconnected`);
        broadcastToAdmins(Buffer.from(JSON.stringify({ type: "device_disc" })));


        break;
      }
    }
  });
});

// Send Push Notification to User
async function sendPushNotification(userId, order, isComplete = false) {
  try {
    // Fetch the user's FCM token from the database
    const user = await User.findById(userId);
    if (!user || !user.fcmToken) {
      console.log("FCM Token not found for user:", userId);
      return;
    }

    let title, body;
    
    if (isComplete) {
      title = "Fuel Dispensing Complete";
      body = `Your fuel order (${order.fuelType}, ${order.amount}L) has been successfully dispensed.`;
    } else {
      title = "Fuel Dispensing Ready";
      body = `Your vehicle has been detected at the fuel station. Confirm to dispense ${order.amount}L of ${order.fuelType}.`;
    }

    const message = {
      notification: {
        title: title,
        body: body,
      },
      data: {
        orderId: order._id.toString(),
        status: order.status,
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

// Function to ping all connected devices periodically
function pingAllDevices() {
  for (const [deviceId, socket] of deviceSockets.entries()) {
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({
        type: "ping",
        timestamp: Date.now()
      }));
    }
  }
}
const path = require("path");
const { Console } = require("console");
app.get("/", (req, res) => {
  const token = req.cookies.adminToken
  console.log(token)

  if (!token) {
      return res.sendFile(path.join(__dirname, "public/login.html")); // Send login page if no token
  }

  // Verify token
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
      if (err) {
          return res.sendFile(path.join(__dirname, "public/login.html")); // If invalid token, show login page
      }
      res.sendFile(path.join(__dirname, "public/admin.html")); // If valid token, serve admin panel
  });
});

// Admin login route - sets cookie and serves admin.html
app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;

  // Replace with actual database check
  const adminUser = { username: "admin", password: "admin123" };

  if (username !== adminUser.username || password !== adminUser.password) {
      return res.status(401).json({ error: "Invalid credentials" });
  }

  // Generate JWT token (no expiration)
  const token = jwt.sign({ admin: username }, SECRET_KEY);

  // Set cookie and send admin.html
  res.cookie("adminToken", token, { httpOnly: true, secure: false });
  res.json({ redirect: "/" }); // Frontend will redirect
});

// Admin logout - clears token and redirects to login
app.post("/admin/logout", (req, res) => {
  res.clearCookie("adminToken");
  res.json({ redirect: "/" }); // Redirect back to login page
});
app.get("/admin/data", authenticateAdmin, async (req, res) => {
  try {
      let vehicles = await Vehicle.find();
      var orders = await FuelOrder.find().lean().sort({date:-1}).populate({
        path: "vehicleId", // Populating vehicleId
        select: "registrationNo" // Selecting the 'registrationNo' (vehicleNumber) field
      });
      vehicles = await Promise.all(
        vehicles.map(async (vehicle) => {
            const owner = await User.findById(vehicle.userId).select("username"); // Get only username
            return {
                ...vehicle.toObject(), // Ensure it's a plain object
                owner: owner ? owner.username : "Unknown"
            };
        })
    );
      orders = await Promise.all(
        orders.map(async (order) => {
            const owner = await User.findById(order.userId).select("username"); // Get only username
            return {
                ...order, // Spread order object (Mongoose already returns plain JS objects)
                owner: owner ? owner.username : "Unknown" // Attach owner username
            };
        })
    );
    
    
    // Map over the orders to include vehicleNumber directly in the response
    orders = orders.map(order => {
      return {
        ...order,
        vehicleNumber: order.vehicleId.registrationNo 
      };
    });
    const devices = [];

        for (const [deviceId, socket] of deviceSockets.entries()) {
            devices.push({
                deviceId,
                status: socket.readyState === WebSocket.OPEN ? "Connected" : "Disconnected"
            });
        }

      res.json({ vehicles, orders ,devices});
  } catch (error) {
      console.error("Error fetching data:", error);
      res.status(500).json({ message: "Internal Server Error" });
  }
});
// Set up periodic ping every 30 seconds
setInterval(pingAllDevices, 30000);

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});