function base64urlEncode(obj) {
  return Buffer.from(JSON.stringify(obj))
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

const header = {
  alg: "NONE",
  typ: "JWT",
};

const payload = {
  id: 1,
  username: "admin",
  role: "admin",
};

const token = `${base64urlEncode(header)}.${base64urlEncode(payload)}.`;

console.log(token);
