const mongoose = require("mongoose")

const connectDB = async () => {
  try {
    await mongoose.connect("mongodb://localhost:27017/logAnalysis", {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    })
    console.log("MongoDB connected for Log Analysis Dashboard")
  } catch (err) {
    console.error(err.message)
    process.exit(1)
  }
}

module.exports = connectDB
