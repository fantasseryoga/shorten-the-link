const {Router} = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')
const router = Router()


router.post(
    '/register',
    [
        check('email', 'Incorrect email').isEmail(),
        check('password', 'Minimum length of password is 6 symbols').isLength({min: 6})
    ],
    async (req, res) => {
    try{
        console.log(req.body)

        const errors = validationResult(req)

        if(!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'Incorrect data'
            })
        }

        const {email, password} = req.body
        const candidate = await User.findOne({ email: email})

        if(candidate) {
            return res.status(400).json({ message: "This user exists" })
        }

        const hashedPassword = await bcrypt.hash(password, 12)
        const user = new User({ email, password: hashedPassword })

        await user.save()

        res.status(201).json({ message: "User has beed created "})

    } catch (e) {
        res.status(500).json({ message: 'Somthing went wrong, try again. '})
    }
})

router.post(
    '/login',
    [
        check('email', 'Enter correct email').normalizeEmail({ gmail_remove_dots: false }).isEmail(),
        check('password', 'Ebter password').exists()
    ],
    async (req, res) => {
    try{
        const errors = validationResult(req)

        if(!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'Incorrect data'
            })
        }

        const {email, password} = req.body
        const user = await User.findOne({ email })
        if (!user){
            return res.status(400).json({message: "User has not been found"})
        }

        const isMatch = bcrypt.compare(password, user.password)

        if (!isMatch){
            return res.status(400).json({message: "Incorrect Password, try again"})
        }

        const token = jwt.sign(
            { userId: user.id },
            config.get('jwtSecret'),
            { expiresIn: '1h' }
        )

        res.json({ token, userId: user.id })

    } catch (e) {
        res.status(500).json({ message: 'Somthing went wrong, try again. '})
    }     
})


module.exports = router