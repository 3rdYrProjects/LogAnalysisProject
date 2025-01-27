const MongoClient = require("mongodb").MongoClient

const userLogsUri = "mongodb://localhost:27017/userWebsite"
const logAnalysisUri = "mongodb://localhost:27017/logAnalysis"

async function transferLogs() {
  const userLogsClient = new MongoClient(userLogsUri)
  const logAnalysisClient = new MongoClient(logAnalysisUri)

  try {
    await userLogsClient.connect()
    await logAnalysisClient.connect()

    const userLogsDb = userLogsClient.db("userWebsite")
    const logAnalysisDb = logAnalysisClient.db("logAnalysis")

    const logs = await userLogsDb
      .collection("logs")
      .find({ transferred: { $ne: true } })
      .toArray()

    if (logs.length > 0) {
      const formattedLogs = logs.map((log) => ({
        timestamp: log.timestamp,
        userId: log.userId,
        ipAddress: log.ipAddress,
        activity: log.activity,
        details: log.details,
        transferred: true,
      }))
      await logAnalysisDb.collection("logs").insertMany(formattedLogs)

      const logIds = logs.map((log) => log._id)
      await userLogsDb
        .collection("logs")
        .updateMany({ _id: { $in: logIds } }, { $set: { transferred: true } })

      console.log(`${logs.length} logs transferred successfully.`)
    } else {
      console.log("No new logs to transfer.")
    }
  } catch (err) {
    console.error("Error transferring logs:", err)
  } finally {
    await userLogsClient.close()
    await logAnalysisClient.close()
  }
}

setInterval(transferLogs, 5000)
