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
		const allowedType = parameters[param]
		if (bodyParam === undefined) {
			errors.push(`"${param}" needs to be defined.`)
			invalid = true
		} else if (typeof(bodyParam) !== allowedType) {
			errors.push(`"${param}" needs to be a ${allowedType}, not a ${typeof(bodyParam)}.`)
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

function invalidUsernameLength(res, username) {
	const invalid = username.length > maxUsernameLength
	if (invalid) {
		res.status(400).send(`Username should be no more than ${maxUsernameLength} characters long. Right now it is ${username.length} characters long.`)
	}
	return invalid
}

function databaseError(res) {
	res.status(503).send("Database error :(")
}

function getJWT(req, res) {
	const authHeader = req.headers["authorization"]
	if (authHeader === undefined) {
		res.status(400).send("No JWT >:|")
		return false
	}

	const token = authHeader.slice(7)

	try {
		const decoded = jwt.verify(token, tokenSecret)
		return decoded
	} catch (err) {
		console.log(err)
		res.status(403).send("Invalid JWT >:|")
		return false
	}
}

const port = 3000

const tokenHours = 1
const tokenSecret = hash(":^D")

const maxUsernameLength = 30

const app = express()
app.use(bodyParser.json())

app.listen(port, () => {
	console.log(`Server listening on port: ${port}`)
})

app.get("/", (req, res) => {
	res.sendFile(__dirname + "/index.html")
})

app.get("/users", async (req, res) => {
	const JWT = getJWT(req, res)
	if (!JWT) { return }

	const result = await db.SELECT("SELECT * FROM users")
	if (result) {
		res.send(result)
	} else {
		databaseError(res)
	}
})

app.get("/users/:specifier", async (req, res) => {
	const JWT = getJWT(req, res)
	if (!JWT) { return }

	const specifier = req.params.specifier

	const sql = db.prepSQL("SELECT * FROM users WHERE id = ? OR username = ?", [specifier, specifier])
	const result = await db.SELECT(sql)
	if (result) {
		res.send(result)
	} else {
		databaseError(res)
	}
})

app.post("/sign-up", async (req, res) => {
	if (invalidJSON(req, res, {
		username: "string",
		password: "string"
	})) { return }

	const username =      req.body.username
	const password = hash(req.body.password)

	if (invalidUsernameLength(res, username)) { return }

	let sql = db.prepSQL("SELECT * FROM users WHERE username = ?", [username])
	let result = await db.SELECT(sql)
	if (!result) {
		databaseError(res)
		return
	}

	const valid = result.length === 0
	if (valid) {
		sql = db.prepSQL("INSERT INTO users (username, password) VALUES (?, ?)", [username, password])
		result = await db.EXECUTE(sql)
		if (!result) {
			databaseError(res)
			return
		}
		res.send(`User "${username}" was created successfully.`)
	}
	else {
		res.status(409).send(`User "${username}" already exists.`)
	}
})

app.post("/sign-in", async (req, res) => {
	if (invalidJSON(req, res, {
		username: "string",
		password: "string"
	})) { return }

	const username =      req.body.username
	const password = hash(req.body.password)

	const sql = db.prepSQL("SELECT * FROM users WHERE username = ? AND password = ?", [username, password])
	const result = await db.SELECT(sql)
	if (!result) {
		databaseError(res)
		return
	}

	const valid = result.length === 1
	if (valid) {
		const user = result[0]
		const token = jwt.sign({
			sub: user.id,
			username: user.username
		}, tokenSecret, { expiresIn: 60 * 60 * tokenHours })
		res.send("JWT below :o" + "<br>" + token)
	} else {
		res.status(401).send("Invalid credentials.")
	}
})

app.put("/change-username", async (req, res) => {
	const JWT = getJWT(req, res)
	if (!JWT) { return }

	if (invalidJSON(req, res, {
		username: "string"
	})) { return }

	const username = req.body.username

	if (invalidUsernameLength(res, username)) { return }

	let sql = db.prepSQL("SELECT * FROM users WHERE username = ?", [username])
	let result = await db.SELECT(sql)
	if (!result) {
		databaseError(res)
		return
	}

	const id = JWT.sub

	const valid = result.length === 0
	if (valid) {
		sql = db.prepSQL("UPDATE users SET username = ? WHERE id = ?", [username, id])
		result = await db.EXECUTE(sql)
		if (!result) {
			databaseError(res)
			return
		}
		res.send(`Your new username is ${username}.`)
	} else {
		if (id === result[0].id) {
			res.send(`You are already called "${username}".`)
		} else {
			res.send(`The username "${username}" is already in use.`)
		}
	}
})
