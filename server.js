// npm packages
const bodyParser = require("body-parser")
const crypto     = require("crypto")
const express    = require("express")
const jwt        = require("jsonwebtoken")
// services
const db = require("./services/db")

function hash(data) {
	const hash = crypto.createHash("sha256")
	hash.update(data)
	return hash.digest("hex")
}

function invalidJSON(req, res, parameters) {
	let invalid = false
	const errors = []

	Object.keys(parameters).forEach((param) => {
		const bodyParam = req.body[param]
		const allowedType = parameters[param]["type"]
		const allowedMaxLength = parameters[param]["maxLength"]

		if (bodyParam === undefined) {
			errors.push(`"${param}" needs to be defined.`)
			invalid = true
		} else if (typeof(bodyParam) !== allowedType) {
			errors.push(`"${param}" needs to be a ${allowedType}, not a ${typeof(bodyParam)}.`)
			invalid = true
		} else if (bodyParam.length > allowedMaxLength) {
			errors.push(`"${param}" needs to be less than ${allowedMaxLength} characters long. Right now it is ${bodyParam.length} characters long.`)
			invalid = true
		}
	})

	let errorText = ""
	errors.forEach((error) => {
		errorText += error + "<br>"
	})

	if (invalid) {
		res.status(400).send("Invalid JSON >:|" + "<br>" + "See errors below:" + "<br>" + errorText)
	}

	return invalid
}

function databaseError(res) {
	res.status(503).send("Database error :(")
}

async function verifyJWT(req, res) {
	const authHeader = req.headers["authorization"]
	if (authHeader === undefined) {
		res.status(400).send("No JWT >:|")
		return false
	}

	const token = authHeader.slice(7)

	try {
		const decoded = jwt.verify(token, tokenSecret)

		const id = decoded.sub
		const sql = db.prepSQL("SELECT * FROM users WHERE id = ?", [id])
		const result = await db.SELECT(sql)
		if (!result) { databaseError; return }

		const valid = result.length === 1
		if (valid) { return true }

		res.status(403).send("You don't exist ¯\\_(ツ)_/¯")
	} catch (err) {
		console.log(err)
		res.status(403).send("Invalid JWT >:|")
	}

	return false
}

function getJWT(req) {
	const authHeader = req.headers["authorization"]
	const token = authHeader.slice(7)
	const decoded = jwt.verify(token, tokenSecret)
	return decoded
}

async function getUsers(req, res, sql) {
	const result = await db.SELECT(sql)
	if (result) { res.send(result)
	} else { databaseError(res) }
}

// middleware
function requestLogger(req, res, next) {
	const date = Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "long"}).format(Date.now())
	console.log(`${req.ip} [${date}] ${req.method} ${req.url}`)
	next()
}

async function authentication(req, res, next) {
	const valid = await verifyJWT(req, res)
	if (valid) { next() }
}

const port = 3000

const tokenHours = 1
const tokenSecret = hash(":^D")

const maxUsernameLength = 30
const maxPasswordLength = 30

const app = express()
app.use(bodyParser.json())

app.use(requestLogger)

app.listen(port, () => {
	console.log(`Server listening on port: ${port}`)
})

app.get("/", (req, res) => {
	res.sendFile(__dirname + "/index.html")
})

app.get("/users/me", authentication, async (req, res) => {
	res.send(getJWT(req))
})

app.get("/users", authentication, async (req, res) => {
	getUsers(req, res, "SELECT id, username FROM users")
})

app.get("/users/:specifier", authentication, async (req, res) => {
	const specifier = req.params.specifier
	const sql = db.prepSQL("SELECT id, username FROM users WHERE id = ? OR username = ?", [specifier, specifier])
	getUsers(req, res, sql)
})

app.post("/sign-up", async (req, res) => {
	if (invalidJSON(req, res, {
		username: { type: "string", maxLength: maxUsernameLength },
		password: { type: "string", maxLength: maxPasswordLength }
	})) { return }

	const username = req.body.username
	const password = req.body.password

	let sql = db.prepSQL("SELECT * FROM users WHERE username = ?", [username])
	let result = await db.SELECT(sql)
	if (!result) { databaseError; return }

	const valid = result.length === 0
	if (valid) {
		const salt = crypto.randomBytes(4).toString("hex")
		const hashedPassword = hash(salt + password)
		sql = db.prepSQL("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)", [username, hashedPassword, salt])
		result = await db.EXECUTE(sql)
		if (!result) { databaseError; return }
		res.send(`User "${username}" was created successfully.`)
	}
	else {
		res.status(409).send(`User "${username}" already exists.`)
	}
})

app.post("/sign-in", async (req, res) => {
	if (invalidJSON(req, res, {
		username: { type: "string", maxLength: maxUsernameLength },
		password: { type: "string", maxLength: maxPasswordLength }
	})) { return }

	const username = req.body.username

	let sql = db.prepSQL("SELECT salt FROM users WHERE username = ?", [username])
	let result = await db.SELECT(sql)
	if (!result) { databaseError; return }

	let valid = result.length === 1

	if (valid) {
		const salt = result[0].salt

		const hashedPassword = hash(salt + req.body.password)
	
		sql = db.prepSQL("SELECT * FROM users WHERE username = ? AND password = ?", [username, hashedPassword])
		result = await db.SELECT(sql)
		if (!result) { databaseError; return }
	
		valid = result.length === 1
		if (valid) {
			const user = result[0]
			const token = jwt.sign({
				sub: user.id,
				username: user.username
			}, tokenSecret, { expiresIn: 60 * 60 * tokenHours })
			res.send(token)
			return
		}
	}

	res.status(401).send("Invalid credentials.")
})

app.put("/change-username", authentication, async (req, res) => {
	const JWT = getJWT(req)

	if (invalidJSON(req, res, {
		username: { type: "string", maxLength: maxUsernameLength }
	})) { return }

	const username = req.body.username

	let sql = db.prepSQL("SELECT * FROM users WHERE username = ?", [username])
	let result = await db.SELECT(sql)
	if (!result) { databaseError; return }

	const id = JWT.sub

	const valid = result.length === 0
	if (valid) {
		sql = db.prepSQL("UPDATE users SET username = ? WHERE id = ?", [username, id])
		result = await db.EXECUTE(sql)
		if (!result) { databaseError; return }
		res.send(`Your new username is "${username}".`)
	} else {
		if (id === result[0].id) {
			res.send(`You are already called "${username}".`)
		} else {
			res.send(`The username "${username}" is already in use.`)
		}
	}
})
