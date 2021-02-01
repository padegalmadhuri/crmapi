const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const mongodb = require("mongodb");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { query } = require("express");

const port = process.env.PORT || 3000;
dotenv.config();

const key = process.env.KEY;
const saltRounds = 6;
const tokenExpiery = { login: 60 * 24, passwordReset: 10 };

app.use(bodyParser.json());

app.use(cors());

app.use(cookieParser());

app.listen(port, () => {
  console.log("app listing in port " + port);
});
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.C_EMAIL,
    pass: process.env.C_PASSWORD,
  },
});

async function Mail(toMail, link, data) {
  let mailOptions = {
    from: process.env.C_EMAIL,
    to: toMail,
    subject: "verification link",

    html: `<p>${data}</p></br>
    <a href=${link}>Click HERE</a>`,
  };
  return new Promise((resolve, reject) => {
    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log("error is " + error);
        reject(error);
      } else {
        console.log("Email sent: " + info.response);
        resolve("mailed");
      }
    });
  });
}
const uri ="mongodb+srv://Madhuri:sreedhar123@cluster0.uzatp.mongodb.net/crmdata?retryWrites=true&w=majority"
// const uri = `mongodb://localhost:27017/?readPreference=primary&ssl=false`;
const dbName = "crmdata";
const collName1 = "users";
const collName2 = "leads";
const collName3 = "requests";
const collName4 = "contacts";
 
const mongoClient = mongodb.MongoClient;


const verifySession = async (req, res, next) => {
  if (!req.headers["jwt"]) {
    res.status(400).json({
      message: "token missing",
    });
    return;
  }
  let token = req.headers["jwt"];
  let data;
  try {
    data = jwt.verify(token, key);
  } catch (err) {
    res.status(401).json({ message: "session ended login again" });
    return;
  }
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  const collection = client.db(dbName).collection(collName1);
  if (data["type"] == "login") {
    try {
      let result = await collection.findOne({ email: data["email"] });
      if (!result) {
        res.status(500).json({ message: "email couldn't be verified" });
        return;
      } else {
        next({ name: result.name, role: result.role });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "filed to retreive" });
      return;
    } finally {
      client.close();
    }
  } else {
    res.status(401).json({ message: "token error" });
    client.close();
  }
};

const verifyAccess = (Role) => async (user, req, res, next) => {
  if (user.role <= Role) {
    next(user);
  } else res.status(400).json({ message: "you dont have permission" });
};





app.post("/login", async function (req, res) {
  if (!req.body["email"] || !req.body["password"]) {
    res.status(400).json({
      message: "email or password missing",
    });
    return;
  }
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  const collection = client.db(dbName).collection(collName1);
  let result;
  try {
    result = await collection.findOne({ email: req.body["email"] });
    if (!result) {
      res.status(400).json({ message: "email is not registered" });
      return;
    } else if (result["verified"] !== true) {
      res.status(400).json({ message: "email is not verified" });
      return;
    } else if (result["role"] > 4) {
      res.status(400).json({ message: "You are not yet admitted" });
      return;
    }
  } catch (err) {
    res.status(500).json({ message: "filed to retreive" });
  } finally {
    client.close();
  }
  try {
    let pass = await bcrypt.compare(req.body["password"], result["password"]);
    if (!pass) {
      res.status(401).json({ message: "wrong password" });
    } else if (pass) {
      let token_expiry = tokenExpiery["login"];
      let token = jwt.sign({ email: req.body["email"], type: "login" }, key, {
        expiresIn: token_expiry + "m",
      });
      let userData = { name: result["name"], email: result["email"] };
      res
        .status(200)
        .json({ message: "credentials verified!", token, userData });
    }
  } catch {
    res.status(500).json({ message: "couldn't verify password" });
  }
});

app.post("/register", async function (req, res) {
  if (!req.body["email"] || !req.body["password"] || !req.body["name"]) {
    res.status(400).json({
      message: "email or password or name missing",
    });
    return;
  }
  try {
    let hash = await bcrypt.hash(req.body["password"], saltRounds);
    req.body["password"] = hash;
  } catch {
    res.status(400).json({
      message: "hashing failed",
    });
    return;
  }

  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  const collection = client.db(dbName).collection(collName1);
  try {
    let result = await collection.findOne({ email: req.body["email"] });
    if (result) {
      res.status(400).json({ message: "email already exists" });
      return;
    }
  } catch (err) {
    res.status(500).json({ message: "filed to retreive" });
    client.close();
    return;
  }
  try {
    let new_obj = {
      email: req.body.email,
      name: req.body.name,
      password: req.body.password,
      verified: false,
      role: 5,
    };
    await collection.insertOne(new_obj);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "filed to register" });
    return;
  } finally {
    client.close();
  }
  let token = jwt.sign(
    { email: req.body["email"], type: "mailVerification" },
    key
  );
  let link = process.env.APPLINK + "/login/" + token;
  let text = `use token to verify: ${token}`;
  let result = await Mail(req.body["email"], link, text).catch((err) => {
    res.status(500).json({ message: "filed to send mail" });
  });
  if (result) {
    res
      .status(200)
      .json({ message: "verification mail send to " + req.body["email"] });
  }
});

app.post("/verifyEmail", async function (req, res) {
  if (!req.body["jwt"]) {
    res.status(400).json({
      message: "token missing",
    });
    return;
  }
  let token = req.body["jwt"];
  let data;
  try {
    data = jwt.verify(token, key);
  } catch (err) {
    res.status(401).json({ message: "invalid token" });
    return;
  }
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  const collection = client.db(dbName).collection(collName1);
  if (data["type"] == "mailVerification") {
    try {
      let result = await collection.updateOne(
        { email: data["email"] },
        { $set: { verified: true } }
      );
      if (!result.matchedCount) {
        res.status(500).json({ message: "email couldn't be verified" });
        return;
      } else {
        res
          .status(200)
          .json({ message: "your email has been verified you can login now" });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "filed to retreive" });
      return;
    } finally {
      client.close();
    }
  } else {
    res.status(401).json({ message: "token error" });
  }
});

app.post("/resetPassLink", async function (req, res) {
  if (!req.body["email"]) {
    res.status(400).json({
      message: "email  missing",
    });
    return;
  }
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  const collection = client.db(dbName).collection(collName1);
  try {
    let result = await collection.findOne({ email: req.body["email"] });
    if (!result) {
      res.status(400).json({ message: "email is not registered" });
      return;
    } else if (result["verified"] !== true) {
      res.status(400).json({ message: "email is not verified" });
      return;
    }
  } catch (err) {
    res.status(500).json({ message: "filed to retreive" });
    client.close();
    return;
  }

  let token_expiry = tokenExpiery["passwordReset"];
  let token = jwt.sign(
    { email: req.body["email"], type: "passwordReset" },
    key,
    { expiresIn: token_expiry + "m" }
  );
  let link = process.env.APPLINK + "/#/resetpass/" + token;
  let text = `reset password token is valid only for ${token_expiry} minute(s)
                token is : ${token}`;
  let result = await Mail(req.body["email"], link, text).catch((err) => {
    res.status(500).json({ message: "filed to send mail" });
  });
  if (result) {
    res
      .status(200)
      .json({ message: "reset link send to " + req.body["email"] });
  }
});

app.post("/resetPass", async function (req, res) {
  if (!req.body["jwt"] || !req.body["password"]) {
    res.status(400).json({
      message: "token or password missing",
    });
    return;
  }
  let token = req.body["jwt"];
  let data;
  try {
    data = jwt.verify(token, key);
  } catch (err) {
    res.status(401).json({ message: "invalid token" });
    return;
  }
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  const collection = client.db(dbName).collection(collName1);
  if (data["type"] == "passwordReset") {
    //new pass
    let hash;
    try {
      hash = await bcrypt.hash(req.body["password"], saltRounds);
    } catch {
      res.status(400).json({
        message: "hashing failed",
      });
      return;
    }
    //set new pass
    try {
      let result = await collection.updateOne(
        { email: data["email"] },
        { $set: { password: hash } }
      );
      if (!result.matchedCount) {
        res.status(500).json({ message: "email couldn't be verified" });
        return;
      } else {
        res.status(200).json({
          message: "your password has been reset",
        });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "filed to retreive" });
      return;
    } finally {
      client.close();
    }
  } else {
    res.status(401).json({ message: "token error" });
    client.close();
  }
});

app.post(
  "/addLead",
  verifySession,
  verifyAccess(3),
  async (user, req, res, next) => {
    if (
      !req.body["lead_name"] ||
      !req.body["details"] ||
      !req.body["status"] ||
      !req.body["email"]
    ) {
      res.status(400).json({
        message: "bad request",
      });
      return;
    }
    let status_choise = [
      "new",
      "contacted",
      "quantified",
      "lost",
      "cancelled",
      "confirmed",
    ];
    if (!status_choise.includes(req.body["status"])) {
      res.status(400).json({
        message: "bad request (wrong status code)",
      });
      return;
    }
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "filed to connect db" });
      });
    if (!client) {
      return;
    }

    const collection = client.db(dbName).collection(collName2);

    let result;
    try {
      result = await collection.findOne({
        email: req.body.email,
      });
    } catch {
      console.log(err);
      res.status(500).json({ message: "failed to contact db" });
      client.close();
      return;
    }
    if (result) {
      res.status(400).json({ message: "lead already exists" });
      client.close();
      return;
    }
    try {
      let new_obj = {
        lead_name: req.body.lead_name,
        added_by: user.name,
        status: req.body.status,
        details: req.body.details,
        email: req.body.email,
      };
      await collection.insertOne(new_obj);
      res.status(200).json({ message: "added" });
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "failed to add" });
      return;
    } finally {
      client.close();
    }
  }
);

app.get(
  "/getLeads/:id?",
  verifySession,
  verifyAccess(4),
  async (user, req, res, next) => {
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "filed to connect db" });
      });
    if (!client) {
      return;
    }
    let id = null;
    if (req.params.hasOwnProperty("id")) id = req.params["id"];
    const collection = client.db(dbName).collection(collName2);
    try {
      if (!id) {
        let results = await collection.find({}).toArray();
        res.status(200).json({ results });
      } else {
        let result = await collection.findOne({
          _id: mongodb.ObjectID(id),
        });
        res.status(200).json({ result });
      }
    } catch (err) {
      res.status(500).json({ message: "filed to retreive" });
    } finally {
      client.close();
      return;
    }
  }
);

app.put(
  "/updateLead",
  verifySession,
  verifyAccess(3),
  async (user, req, res, next) => {
    if (!req.body["lead_id"] || !req.body["status"]) {
      res.status(400).json({
        message: "bad request",
      });
      return;
    }
    let status_choise = [
      "new",
      "contacted",
      "quantified",
      "lost",
      "cancelled",
      "confirmed",
    ];
    if (!status_choise.includes(req.body["status"])) {
      res.status(400).json({
        message: "bad request (wrong status code)",
      });
      return;
    }
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "filed to connect db" });
      });
    if (!client) {
      return;
    }
    const collection = client.db(dbName).collection(collName2);
    try {
      let result = await collection.updateOne(
        { _id: mongodb.ObjectID(req.body.lead_id) },
        { $set: { status: req.body.status } }
      );
      if (!result.matchedCount) {
        res.status(500).json({ message: "lead_id doesnt exist" });
        return;
      } else {
        res.status(200).json({
          message: "status updated",
        });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "filed to update" });
      return;
    } finally {
      client.close();
    }
  }
);

app.delete(
  "/deleteLead",
  verifySession,
  verifyAccess(3),
  async (user, req, res, next) => {
    if (!req.headers["id"]) {
      res.status(400).json({
        message: "bad request",
      });
      return;
    }
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "filed to connect db" });
      });
    if (!client) {
      return;
    }
    const collection = client.db(dbName).collection(collName2);
    try {
      let result = await collection.deleteOne({
        _id: mongodb.ObjectID(req.headers.id),
      });
      if (!result.deletedCount) {
        res.status(500).json({ message: "lead_id doesnt exist" });
        return;
      } else {
        res.status(200).json({
          message: "lead deleated",
        });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "filed to delete" });
      return;
    } finally {
      client.close();
    }
  }
);

app.post(
  "/addServiceTicket",
  verifySession,
  verifyAccess(3),
  async (user, req, res, next) => {
    console.log(req.body);
    if (
      !req.body["contact_name"] ||
      !req.body["ticket_name"] ||
      !req.body["details"] ||
      !req.body["status"]
    ) {
      res.status(400).json({
        message: "bad request",
      });
      return;
    }
    let status_choise = [
      "created",
      "open",
      "in-process",
      "released",
      "cancelled",
      "completed",
    ];
    if (!status_choise.includes(req.body["status"])) {
      res.status(400).json({
        message: "bad request (wrong status code)",
      });
      return;
    }
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "filed to connect db" });
      });
    if (!client) {
      return;
    }
    const collection = client.db(dbName).collection(collName3);
    try {
      let new_obj = {
        contact_name: req.body.contact_name,
        ticket_name: req.body.ticket_name,
        added_by: user.name,
        status: req.body.status,
        details: req.body.details,
      };
      await collection.insertOne(new_obj);
      res.status(200).json({ message: "added" });
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "failed to add" });
      return;
    } finally {
      client.close();
    }
  }
);

app.get(
  "/getServiceTickets/:id?",
  verifySession,
  verifyAccess(4),
  async (user, req, res, next) => {
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "failed to connect db" });
      });
    if (!client) {
      return;
    }
    let id = null;
    if (req.params.hasOwnProperty("id")) id = req.params["id"];
    const collection = client.db(dbName).collection(collName3);
    try {
      if (!id) {
        let results = await collection.find({}).toArray();
        res.status(200).json({ results });
      } else {
        let result = await collection.findOne({
          _id: mongodb.ObjectID(id),
        });
        res.status(200).json({ result });
      }
    } catch (err) {
      res.status(500).json({ message: "failed to retreive" });
    } finally {
      client.close();
      return;
    }
  }
);

app.put(
  "/updateServiceTicket",
  verifySession,
  verifyAccess(3),
  async (user, req, res, next) => {
    if (!req.body["ticket_id"] || !req.body["status"]) {
      res.status(400).json({
        message: "bad request",
      });
      return;
    }
    let status_choise = [
      "created",
      "open",
      "in-process",
      "released",
      "cancelled",
      "completed",
    ];
    if (!status_choise.includes(req.body["status"])) {
      res.status(400).json({
        message: "bad request (wrong status code)",
      });
      return;
    }
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "failed to connect db" });
      });
    if (!client) {
      return;
    }
    const collection = client.db(dbName).collection(collName3);
    try {
      let result = await collection.updateOne(
        { _id: mongodb.ObjectID(req.body.ticket_id) },
        { $set: { status: req.body.status } }
      );
      if (!result.matchedCount) {
        res.status(500).json({ message: "ticket_id doesnt exist" });
        return;
      } else {
        res.status(200).json({
          message: "status updated",
        });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "failed to update" });
      return;
    } finally {
      client.close();
    }
  }
);

app.delete(
  "/deleteServiceTicket",
  verifySession,
  verifyAccess(3),
  async (user, req, res, next) => {
    if (!req.headers["id"]) {
      res.status(400).json({
        message: "bad request",
      });
      return;
    }
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "filed to connect db" });
      });
    if (!client) {
      return;
    }
    const collection = client.db(dbName).collection(collName3);
    try {
      let result = await collection.deleteOne({
        _id: mongodb.ObjectID(req.headers.id),
      });
      if (!result.deletedCount) {
        res.status(500).json({ message: "ticket_id doesnt exist" });
        return;
      } else {
        res.status(200).json({
          message: "ticket deleated",
        });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "filed to delete" });
      return;
    } finally {
      client.close();
    }
  }
);

app.get(
  "/getUsers/:id?",
  verifySession,
  verifyAccess(2),
  async (user, req, res, next) => {
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "failed to connect db" });
      });
    if (!client) {
      return;
    }
    let id = null;
    if (req.params.hasOwnProperty("id")) id = req.params["id"];
    const collection = client.db(dbName).collection(collName1);
    try {
      let query = user.role == 2 ? { role: { $gt: 2 } } : { role: { $gt: 1 } };
      if (!id) {
        let results = await collection.find(query).toArray();
        res.status(200).json({ results });
      } else {
        let result = await collection.findOne({ _id: mongodb.ObjectID(id) });
        res.status(200).json({ result });
      }
    } catch (err) {
      res.status(500).json({ message: "failed to retreive" });
    } finally {
      client.close();
      return;
    }
  }
);

app.put(
  "/updateUserRole",
  verifySession,
  verifyAccess(2),
  async (user, req, res, next) => {
    let roles = [2, 3, 4, 5];
    if (
      !req.body["role"] ||
      !req.body["user_id"] ||
      !roles.includes(parseInt(req.body.role))
    ) {
      res.status(400).json({
        message: "bad request",
      });
      return;
    }
    if (user.role >= parseInt(req.body.role)) {
      res.status(400).json({
        message: "You dont have permisssion",
      });
      return;
    }

    let role = parseInt(req.body.role);
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "failed to connect db" });
      });
    if (!client) {
      return;
    }
    const collection = client.db(dbName).collection(collName1);
    try {
      let role_access = await collection.findOne({
        _id: mongodb.ObjectID(req.body.user_id),
      });
      if (user.role >= parseInt(role_access.role)) {
        res.status(400).json({
          message: "You dont have permisssion",
        });
        client.close();
        return;
      }
    } catch {
      console.log(err);
      res.status(500).json({ message: "filed to verify access" });
      client.close();
      return;
    }
    try {
      let result = await collection.updateOne(
        { _id: mongodb.ObjectID(req.body.user_id) },
        { $set: { role: role } }
      );
      if (!result.matchedCount) {
        res.status(500).json({ message: "user not found" });
        return;
      } else {
        res.status(200).json({
          message: "role updated",
        });
      }
    } catch (err) {
      res.status(500).json({ message: "failed to retreive" });
    } finally {
      client.close();
      return;
    }
  }
);

app.delete(
  "/deleteUser",
  verifySession,
  verifyAccess(2),
  async (user, req, res, next) => {
    if (!req.headers["id"]) {
      res.status(400).json({
        message: "bad request",
      });
      return;
    }

    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "filed to connect db" });
      });
    if (!client) {
      return;
    }
    const collection = client.db(dbName).collection(collName1);
    try {
      let role_access = await collection.findOne({
        _id: mongodb.ObjectID(req.headers.id),
      });
      if (user.role >= parseInt(role_access.role)) {
        res.status(400).json({
          message: "You dont have permisssion",
        });
        client.close();
        return;
      }
    } catch {
      console.log(err);
      res.status(500).json({ message: "filed to verify access" });
      client.close();
      return;
    }
    try {
      let result = await collection.deleteOne({
        _id: mongodb.ObjectID(req.headers.id),
      });
      if (!result.deletedCount) {
        res.status(500).json({ message: "user_id doesnt exist" });
        return;
      } else {
        res.status(200).json({
          message: "user deleated",
        });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "filed to delete" });
      return;
    } finally {
      client.close();
    }
  }
);

app.post(
  "/createContact",
  verifySession,
  verifyAccess(3),
  async (user, req, res, next) => {
    if (!req.body["contact_name"] || !req.body["email"]) {
      res.status(400).json({
        message: "bad request",
      });
      return;
    }
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "filed to connect db" });
      });
    if (!client) {
      return;
    }

    const collection = client.db(dbName).collection(collName4);

    let result;
    try {
      result = await collection.findOne({
        email: req.body.email,
      });
    } catch {
      console.log(err);
      res.status(500).json({ message: "failed to contact db" });
      client.close();
      return;
    }
    if (result) {
      res.status(400).json({ message: "contact already exists" });
      client.close();
      return;
    }
    try {
      let new_obj = {
        contact_name: req.body.contact_name,
        added_by: user.name,
        email: req.body.email,
        ph: req.body.ph,
      };
      await collection.insertOne(new_obj);
      res.status(200).json({ message: "added" });
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "failed to add" });
      return;
    } finally {
      client.close();
    }
  }
);

app.get(
  "/getContacts/:id?",
  verifySession,
  verifyAccess(4),
  async (user, req, res, next) => {
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "failed to connect db" });
      });
    if (!client) {
      return;
    }
    let id = null;
    if (req.params.hasOwnProperty("id")) id = req.params["id"];
    const collection = client.db(dbName).collection(collName4);
    try {
      if (!id) {
        let results = await collection.find({}).toArray();
        res.status(200).json({ results });
      } else {
        let result = await collection.findOne({
          _id: mongodb.ObjectID(id),
        });
        res.status(200).json({ result });
      }
    } catch (err) {
      res.status(500).json({ message: "failed to retreive" });
    } finally {
      client.close();
      return;
    }
  }
);

app.delete(
  "/deleteContact",
  verifySession,
  verifyAccess(2),
  async (user, req, res, next) => {
    if (!req.headers["id"]) {
      res.status(400).json({
        message: "bad request",
      });
      return;
    }
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "filed to connect db" });
      });
    if (!client) {
      return;
    }
    const collection = client.db(dbName).collection(collName4);
    try {
      let result = await collection.deleteOne({
        _id: mongodb.ObjectID(req.headers.id),
      });
      if (!result.deletedCount) {
        res.status(500).json({ message: "conatct_id doesnt exist" });
        return;
      } else {
        res.status(200).json({
          message: "conatct deleated",
        });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "filed to delete" });
      return;
    } finally {
      client.close();
    }
  }
);

// for dev pass reset
app.get("/hashpass/:str?", async (req, res) => {
  hash = await bcrypt.hash(req.params["str"], saltRounds);
  res.send(hash);
});