const express = require("express");
const nacl = require("tweetnacl");

const app = express();

app.use(express.raw());
const rawMiddleware = (req, res, next) => {
    req.rawBody = "";
    req.setEncoding("utf8");

    req.on("data", function (chunk) {
        req.rawBody += chunk;
    });

    req.on("end", function () {
        next();
    });
};

app.get("/", (req, res) => res.sendStatus(200));

app.post("/", rawMiddleware, (req, res) => {
    // Your public key can be found on your application in the Developer Portal
    const PUBLIC_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

    const signature = req.get("X-Signature-Ed25519");
    const timestamp = req.get("X-Signature-Timestamp");
    const rawBody = req.rawBody; // rawBody is expected to be a string, not raw bytes

    const isVerified = nacl.sign.detached.verify(
        Buffer.from(timestamp + rawBody),
        Buffer.from(signature, "hex"),
        Buffer.from(PUBLIC_KEY, "hex")
    );

    const body = JSON.parse(rawBody);

    console.log(body);

    if (!isVerified) {
        return res.status(401).end("invalid request signature");
    }

    return res.status(200).json({ type: 1 });
});

app.listen(process.env.PORT, () => console.log("Running"));
