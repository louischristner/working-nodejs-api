import express from 'express';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import { validationResult } from 'express-validator';
import { config } from '../store/config';

import {
    generateHashedPassword,
    generateServerErrorCode,
    registerValidation,
    loginValidation,
} from '../store/utils';

import {
    SOME_THING_WENT_WRONG,
    USER_EXISTS_ALREADY,
    WRONG_PASSWORD,
    USER_DOES_NOT_EXIST,
} from '../controller/constant';

import { User } from '../database/models';

const userController = express.Router();

const createUser = (username, password) => {
    const data = {
        username,
        hashedPassword: generateHashedPassword(password),
    };
    return new User(data).save();
}

/**
 * GET/
 * retrieve and display all Users in the User Model
 */
userController.get(
    '/',
    passport.authenticate('jwt', { session: false }),
    (req, res) => {
    User.find({}, (err, result) => {
        res.status(200).json({ data: result });
    });
});

/**
 * POST/
 * Register a user
 */
userController.post('/register', registerValidation, async (req, res) => {
    const errorsAfterValidation = validationResult(req);
    if (!errorsAfterValidation.isEmpty()) {
        return res.status(400).json({
            code: 400,
            errors: errorsAfterValidation.mapped(),
        });
    }

    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });

        if (!user) {
            await createUser(username, password);

            // Sign token
            const newUser = await User.findOne({ username });
            const token = jwt.sign({ username }, config.passport.secret, {
                expiresIn: 10000000,
            });
            const userToReturn = { ...newUser.toJSON(), ...{ token } };

            delete userToReturn.hashedPassword;

            res.status(200).json(userToReturn);
        } else {
            generateServerErrorCode(res, 403, 'register username error', USER_EXISTS_ALREADY, 'username');
        }
    } catch (e) {
        generateServerErrorCode(res, 500, e, SOME_THING_WENT_WRONG);
    }
});

/**
 * POST/
 * Login a user
 */
userController.post('/login', loginValidation, async (req, res) => {
    const errorsAfterValidation = validationResult(req);
    if (!errorsAfterValidation.isEmpty()) {
        return res.status(400).json({
            code: 400,
            errors: errorsAfterValidation.mapped(),
        });
    }

    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && user.username) {
        const isPasswordMatched = user.comparePassword(password);
        if (isPasswordMatched) {
            // Sign token
            const token = jwt.sign({ username }, config.passport.secret,
            {
                expiresIn: 1000000,
            });
            const userToReturn = { ...user.toJSON(), ...{ token } };
            delete userToReturn.hashedPassword;
            res.status(200).json(userToReturn);
        } else {
            generateServerErrorCode(res, 403, 'login password error', WRONG_PASSWORD, 'password');
        }
    } else {
        generateServerErrorCode(res, 404, 'login username error', USER_DOES_NOT_EXIST, 'username');
    }
});

export default userController;
