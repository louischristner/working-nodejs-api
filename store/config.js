export const config = {
    passport: {
        secret: '<Add_Your_Own_Secret_Key>',
        expiresIn: 10000,
    },
    env: {
        port: 8080,
        mongoDBUri: 'mongodb://localhost/test',
        mongoHostName: process.env.ENV === 'prod' ? 'mongodbAtlas' : 'localhost',
    },
};

export const underscoreId = '_id';
