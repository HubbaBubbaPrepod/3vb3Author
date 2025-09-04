const express = require("express")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const app = express()

app.use(express.json())

const JWT_SECRET = "my_super_jwt_secret_12345" // Должен быть очень сложным и храниться в env-переменных!

const users = []

// Функция-мидлвар для проверки JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"]
  // Bearer TOKEN -> получаем сам токен
  const token = authHeader && authHeader.split(" ")[1]

  if (token == null) return res.sendStatus(401) // Если токена нет

  jwt.verify(token, JWT_SECRET, (err, userFromToken) => {
    if (err) return res.sendStatus(403) // Если токен невалидный/просроченный
    req.user = userFromToken // Кладем данные из payload в req.user
    next()
  })
}

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body
    // Хэшируем пароль! (очень важно)
    const hashedPassword = await bcrypt.hash(password, 10)
    users.push({ username, password: hashedPassword })
    res.status(201).send("User registered")
  } catch {
    res.status(500).send()
  }
})
app.post("/login", async (req, res) => {
  const { username, password } = req.body
  const user = users.find(u => u.username === username)
  if (user == null) return res.status(400).send("Cannot find user")

  try {
    if (await bcrypt.compare(password, user.password)) {
      // Создаем JWT! В payload кладем username (не кладите пароль!)
      const token = jwt.sign({ username: user.username }, JWT_SECRET, {
        expiresIn: "1h",
      })
      res.json({ token }) // Отправляем токен клиенту
    } else {
      res.send("Not Allowed")
    }
  } catch {
    res.status(500).send()
  }
})

// Защищенный роут. Используем наш мидлвар.
app.get("/dashboard", authenticateToken, (req, res) => {
  // Теперь в req.user лежит { username: '...' }
  res.send(`Welcome to your JWT dashboard, ${req.user.username}!`)
})

app.listen(3001, () => console.log("JWT Server running on port 3001"))
