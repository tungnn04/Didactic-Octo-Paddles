const jwt = require("jsonwebtoken");
const { tokenKey } = require("../utils/authorization");
const db = require("../utils/database");

// VÁ: chỉ chấp nhận một thuật toán đối xứng cố định, verify bằng key thật,
// không bao giờ truyền key null, không phân biệt hoa/thường ở alg.
const AdminMiddleware = async (req, res, next) => {
  try {
    const sessionCookie = req.cookies.session;
    if (!sessionCookie) return res.redirect("/login");

    // Allowlist cứng — bỏ hoàn toàn nhánh "alg lạ -> verify(null)".
    const user = jwt.verify(sessionCookie, tokenKey, { algorithms: ["HS256"] });

    const admin = await db.Users.findOne({
      where: { id: user.id, username: "admin" },
    });
    if (!admin) return res.status(403).send({ message: "You are not an admin" });

    return next();
  } catch (err) {
    return res.redirect("/login"); // không 'throw err'
  }
};

module.exports = AdminMiddleware;
