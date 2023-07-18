const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('./server'); // your Express app
const User = require('./model/User');
const Token = require('./model/Token');

const SECRET = process.env.SECRET || 'changeme';

jest.mock('./model/User');
jest.mock('./model/Token');

describe('/api', () => {
    afterEach(() => {
        jest.resetAllMocks();
    });

    describe('/login', () => {
        it('logs in a user', async () => {
            const mockUser = { _id: '1', email: 'test@example.com', password: 'hashedPassword' };
            User.findOne.mockResolvedValue(mockUser);
            Token.prototype.save.mockResolvedValue();

            const res = await request(app)
                .post('/api/login')
                .send({ email: 'test@example.com', password: 'password' });
            
            expect(res.status).toEqual(200);
            expect(res.body).toHaveProperty('accessToken');
            expect(res.body).toHaveProperty('expiresAt');
            expect(res.body).toHaveProperty('refreshToken');
        });
    });

    // describe('/register', () => {
    //     it('registers a new user', async () => {
    //         const mockUser = { _id: '1', email: 'test@example.com', firstName: 'John', lastName: 'Doe' };
    //         User.findOne.mockResolvedValue(null);
    //         User.prototype.save.mockResolvedValue(mockUser);
    //         Token.prototype.save.mockResolvedValue();

    //         const res = await request(app)
    //             .post('/api/register')
    //             .send({ email: 'test@example.com', password: 'Password123!', firstName: 'John', lastName: 'Doe' });
            
    //         expect(res.status).toEqual(200);
    //         expect(res.body).toHaveProperty('accessToken');
    //         expect(res.body).toHaveProperty('expiresAt');
    //         expect(res.body).toHaveProperty('refreshToken');
    //     });
    // });

    // describe('/refreshToken', () => {
    //     it('refreshes a user token', async () => {
    //         const mockUser = { _id: '1', email: 'test@example.com' };
    //         Token.findOne.mockResolvedValue({ user: mockUser._id });
    //         User.findOne.mockResolvedValue(mockUser);

    //         const res = await request(app)
    //             .post('/api/refreshToken')
    //             .send({ refreshToken: 'refreshToken' });
            
    //         expect(res.status).toEqual(200);
    //         expect(res.body).toHaveProperty('accessToken');
    //     });
    // });

    // // Assuming that you have a way of mocking axios in your tests
    // describe('/cat', () => {
    //     it('returns a cat image', async () => {
    //         const token = jwt.sign(
    //             {
    //                 sub: '1',
    //                 email: 'test@example.com',
    //                 aud: 'api.example.com',
    //                 iss: 'api.example.com',
    //             }, 
    //             SECRET, 
    //             {
    //                 expiresIn: '1h',
    //                 algorithm: 'HS256'
    //             }
    //         );

    //         // Here you should mock your axios request
    //         // I'm not including this part since it's not clear how your axios instance is structured

    //         const res = await request(app)
    //             .get('/api/cat')
    //             .set('Authorization', `Bearer ${token}`);

    //         expect(res.status).toEqual(200);
    //         // Verify the returned image data based on your mocked axios request
    //     });
    // });
});
