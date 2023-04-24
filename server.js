const bodyParser = require("body-parser")
const crypto     = require("crypto")
const express    = require("express")
const jwt        = require("jsonwebtoken")

const db = require("./db")
const port = 3000
let sql

const app = express()
app.use(bodyParser.json())

function hash(data) {
	const hash = crypto.createHash("sha256")
	hash.update(data)
	return hash.digest("hex")
}

app.listen(port, () => {
	console.log(`Server listening on port: ${port}`)
})

app.get("/", (req, res) => {
	res.sendFile(__dirname + "/index.html")
})

app.get("/users", async (req, res) => {
	const result = await db.SELECT("SELECT * FROM users")
	res.send(result)
})

app.post("/sign-up", async (req, res) => {
	const username =      req.body.username
	const password = hash(req.body.password)

	sql = db.prepSQL("SELECT * FROM users WHERE username = ?", [username])
	const result = await db.SELECT(sql)

	const valid = result.length === 0
	if (valid) {
		sql = db.prepSQL("INSERT INTO users (username, password) VALUES (?, ?)", [username, password])
		await db.INSERT(sql)
	}

	if (valid) {
		res.send(`User "${username}" was created successfully.`)
	}
	else {
		res.send(`User "${username}" already exists.`)
	}
})

app.post("/sign-in", async (req, res) => {
	const username =      req.body.username
	const password = hash(req.body.password)

	sql = db.prepSQL("SELECT * FROM users WHERE username = ? AND password = ?", [username, password])
	const result = await db.SELECT(sql)

	res.send(result)
})
