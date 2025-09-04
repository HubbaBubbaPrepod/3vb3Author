const express = require("express")
const session = require("express-session")
const bcrypt = require("bcrypt")
const app = express()

// Middleware для парсинга JSON и работы с сессиями
app.use(express.json())
app.use(
  session({
    secret: "my_super_secret_key_12345", // Секретный ключ для подписи куки
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 1000 * 60 * 60 * 24 }, // secure:true для HTTPS
  })
)

// "База данных" пользователей (в реальности - настоящая БД)
const users = []

// Роут для регистрации
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

// Роут для логина
app.post("/login", async (req, res) => {
  const { username, password } = req.body
  const user = users.find(u => u.username === username)

  if (user == null) {
    return res.status(400).send("Cannot find user")
  }

  try {
    // Сравниваем хэш из БД с хэшем введенного пароля
    if (await bcrypt.compare(password, user.password)) {
      // Аутентификация успешна! Сохраняем пользователя в сессии.
      req.session.user = username
      res.send("Login Successfully")
    } else {
      res.send("Not Allowed")
    }
  } catch {
    res.status(500).send()
  }
})

// Защищенный роут. Доступен только аутентифицированным пользователям.
app.get("/dashboard", (req, res) => {
  if (req.session.user) {
    res.send(`Welcome to your dashboard, ${req.session.user}!`)
  } else {
    res.status(401).send("Please login first")
  }
})

// Роут для логаута
app.post("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send("Could not log out.")
    }
    res.clearCookie("connect.sid") // Имя куки по умолчанию для express-session
    res.send("Logout successful")
  })
})

app.listen(3000, () => console.log("Session Server running on port 3000"))
