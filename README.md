# Dấu hiệu phát hiện — Didactic-Octo-Paddles

## 1. JWT bất thường

Phát hiện JWT có header `alg` không thuộc allowlist, hoặc phần signature rỗng
(token kết thúc bằng dấu chấm, không có ký tự phía sau).

**Regex nhận dạng unsigned JWT (signature rỗng):**

```
^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.$
```

**Điều kiện bổ sung:** Giải mã Base64URL phần header và kiểm tra trường `alg`.
Nếu `alg` không phải `HS256` (hoặc giá trị trong allowlist đã cấu hình),
token phải bị từ chối và sự kiện phải được ghi log.

## 2. Username chứa cú pháp template (SSTI)

Trong request `POST /register`, nếu trường `username` khớp với biểu thức sau,
đây là dấu hiệu nỗ lực SSTI:

```
\{\{.*\}\}
```

Các biến thể nguy hiểm khác cần giám sát:

- `${...}` — JavaScript template literal / EJS
- `#{...}` — Ruby ERB / Slim
- `<%...%>` — EJS / ASP-style

Hành động khuyến nghị: từ chối đăng ký và log sự kiện ở mức `WARNING`.

## 3. Truy cập /admin đáng ngờ

Ghi log và cảnh báo khi:

- Request `GET /admin` nhận được với cookie `session` là unsigned JWT
  (khớp regex ở mục 1), **và**
- Server trả về HTTP 200 (bypass thành công) thay vì HTTP 302 redirect.

Kết hợp hai tín hiệu này xác nhận alg-confusion bypass đã thành công.
Nếu server trả về HTTP 500, đây là dấu hiệu bug `throw err` trong catch block
đang bị khai thác để probe hành vi của middleware.

## 4. Ví dụ pseudo-rule

```yaml
# Sigma-like pseudo-rule — Didactic-Octo-Paddles attack chain
title: JWT Alg-Confusion + jsrender SSTI Attack Chain
status: experimental
logsource:
  category: webserver
detection:
  unsigned_jwt_admin:
    cs-uri-stem: "/admin"
    cs-cookie|re: '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.$'
    sc-status: "200"
  ssti_register:
    cs-uri-stem: "/register"
    cs-method: "POST"
    request_body|re: '\{\{.*\}\}'
  condition: unsigned_jwt_admin OR ssti_register
falsepositives:
  - Legitimate admin access with misconfigured token library (low probability)
level: critical
```

**Giải thích:**

- Rule `unsigned_jwt_admin`: kích hoạt khi truy cập `/admin` bằng unsigned JWT
  và nhận HTTP 200 — xác nhận bypass.
- Rule `ssti_register`: kích hoạt khi body đăng ký chứa cú pháp template jsrender.
- Hai điều kiện độc lập; chỉ cần một trong hai là đủ để cảnh báo mức `critical`.
