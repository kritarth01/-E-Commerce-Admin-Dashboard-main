const express = require("express");

require("./db/config");

const User = require("./db/model/user");

const Product = require("./db/model/Product");

const cors = require("cors");

const app = express();

const Jwt = require("jsonwebtoken");

const jwtKey = "e-comm";

const bcrypt = require("bcrypt");

const saltRounds = 10;

const salt = bcrypt.genSaltSync(saltRounds);

var PORT = process.env.PORT || 5000;

app.use(express.json());

// app.use(cors());
const corsOptions ={
   origin:'*', 
   credentials:true,            //access-control-allow-credentials:true
   methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
   optionSuccessStatus:200,
}

app.use(cors(corsOptions))

app.post("/register", async (req, res) => {
  let user = new User(req.body);
  let check = await User.findOne({ email: req.body.email }).select("-password");
  if (check != null) res.send(false);
  else {
    let result = await user.save();
    // console.log(result);
    result = result.toObject();
    delete result.password;
    Jwt.sign({ result }, jwtKey, { expiresIn: "48h" }, (err, token) => {
      if (err) res.send("Something went wrong, Please try after somtime");
      else res.send({ result, auth: token });
    });
  }
});

app.post("/login", async (req, res) => {
  if (req.body.email && req.body.password) {
    let user = await User.findOne({ email: req.body.email }).select(
      "-password"
    );
    let hashString = JSON.stringify(
      await User.findOne({ email: req.body.email }).select("password")
    );

    async function validatePassword(plainText, hash) {
      let result = await bcrypt.compare(plainText, hash);
      return result;
    }

    if (user && validatePassword(req.body.password, hashString)) {
      Jwt.sign({ user }, jwtKey, { expiresIn: "2h" }, (err, token) => {
        if (err) {
          res.send("Something went wrong, Please try after somtime");
        } else {
          res.send({ user, auth: token });
        }
      });
    } else res.send({ result: "No User Found!" });
  } else res.send({ result: "No User Found!" });
});

app.post("/add-product", verifyToken, async (req, res) => {
  let product = new Product(req.body);
  let result = await product.save();

  res.send(result);
});

app.get("/products", verifyToken, async (req, res) => {
  let products = await Product.find();
  if (products.length > 0) res.send(products);
  else res.send({ result: "No Products Found!" });
});

app.delete("/product/:id", verifyToken, async (req, res) => {
  const result = await Product.deleteOne({ _id: req.params.id });
  res.send(result);
});

app.get("/product/:id", verifyToken, async (req, res) => {
  let result = await Product.findOne({ _id: req.params.id });

  if (result) res.send(result);
  else res.send({ result: "No Record Found!" });
});

app.put("/product/:id", verifyToken, async (req, res) => {
  let result = await Product.updateOne(
    { _id: req.params.id },
    {
      $set: req.body,
    }
  );
  res.send(result);
});

app.get("/search/:key", verifyToken, async (req, res) => {
  let result = await Product.find({
    $or: [
      { name: { $regex: req.params.key } },
      { name: { $regex: req.params.key.toUpperCase() } },
      // { company: { $regex: req.params.key } },
      // { cateogry: { $regex: req.params.key } },
    ],
  });
  // console.log(res);
  res.send(result);
});

function verifyToken(req, res, next) {
  let token = req.headers["authorization"];

  if (token) {
    token = token.split(" ")[1];
    Jwt.verify(token, jwtKey, (err, valid) => {
      if (err) {
        res.status(401).send({ result: "Please Provide Valid Token" });
      } else {
        next();
      }
    });
  } else {
    res.status(403).send({ result: "Please add token with header" });
  }
}
app.listen(PORT, function (err) {
  if (err) console.log("Error in server setup");
  console.log("Server listening on Port", PORT);
});
