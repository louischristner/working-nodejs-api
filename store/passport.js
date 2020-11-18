import { Strategy, ExtractJwt } from 'passport-jwt';
import { config, underscoreId } from './config';
import { User } from '../database/models';

export const applyPassportStrategy = passport => {
    const options = {};
    options.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
    options.secretOrKey = config.passport.secret;
    passport.use(
        new Strategy(options, (payload, done) => {
            User.findOne({ username: payload.username }, (err, user) => {
                if (err) return done(err, false);
                if (user) {
                    return done(null, {
                        username: user.username,
                        _id: user[underscoreId]
                    });
                }
                return done(null, false);
            });
        })
    );
};
