const handleSignIn = (req, res, db , bcrypt) => {
	const { email, password } = req.body;
	if (!email || !password) {
		return res.status(400).json('incorrect for submission');
	}
	db('login').select('email', 'hash', 'confirmed')
	  .where(db.raw('?? = ?', ['email', email]))
	  .then(data => {
	  	const isValid = bcrypt.compareSync(password, data[0].hash);
	  	if (isValid) {
			if (data[0].confirmed === true ) {
				return db.select('*').from('users')
					.where(db.raw('?? = ?', ['email', email]))
					.then(user => {
						res.json(user[0])
					})
					  .catch(err => res.status(400).json('unable to load user'))
			} else {
				res.status(400).json('profile needs to be validated')
			}
	  	} else {
	  		res.status(400).json('wrong credentials')
	  	}
	  })
	  .catch(err => res.status(400).json('wrong credentials'))
}

module.exports = {
	handleSignIn: handleSignIn
};