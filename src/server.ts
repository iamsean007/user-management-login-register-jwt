import dotenv from 'dotenv';
dotenv.config();
import express, { Request, Response, NextFunction } from 'express';
import jwtDecode from 'jwt-decode';
import jsonwebtoken from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import randToken from 'rand-token';
import cors from 'cors';
import mongoose from 'mongoose';
import { expressjwt } from 'express-jwt';
import axios from 'axios';
import rateLimit from 'express-rate-limit';
import passwordValidator from 'password-validator';

import User from './model/User';
import Token from './model/Token';

const app = express();
const port: number = Number(process.env.PORT) || 3001;

//Generate a random string with command:
//openssl rand -base64 20
const SECRET: string = process.env.SECRET || 'M15VDGBYvvekjBAp9LyCUc/KOyk=';

app.use(cors());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const generateToken = (user: any) => {
    const token: string = jsonwebtoken.sign({
        sub: user._id,
        email: user.email,
        aud: 'api.example.com',
        iss: 'api.example.com',
    }, 
    SECRET,
    {
        expiresIn: '1h',
        algorithm: 'HS256'
    })
    return token;
}

const hashPassword = (password: string) => {
  return new Promise<string>((resolve, reject) => {
    bcrypt.genSalt(10, (err: Error | undefined, salt: string) => {
      if(err) reject(err)
      bcrypt.hash(password, salt, (err: Error | undefined, hash: string) => {
        if(err) reject(err)
        resolve(hash)
      })
    })
  })
}
//Password Policies
const passwordSchema = new passwordValidator();

// Add properties to it
passwordSchema
.is().min(8)                                    // Minimum length 8
.is().max(100)                                  // Maximum length 100
.has().uppercase()                              // Must have uppercase letters
.has().lowercase()                              // Must have lowercase letters
.has().digits(2)                                // Must have at least 2 digits
.has().not().spaces()                           // Should not have spaces
.is().not().oneOf(['Passw0rd', 'Password123']); // Blacklist these values

const checkPassword = (password: string, hash: string) => bcrypt.compare(password, hash);

const getRefreshToken = () => randToken.uid(256);


// Rate limit for login and register routes
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many accounts created from this IP, please try again after an hour'
});

//  Apply to /api/login and /api/register routes
app.use('/api/login', limiter);
app.use('/api/register', limiter);

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error(err.stack);
  res.status(500).send('Something went wrong.');
});

// API ENDPOINTS
app.post('/api/login', async (req: Request, res: Response) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) { 
        return res.status(401).json({
            message: 'User not found!'
        });
    }
    const isPasswordValid = await checkPassword(password, user.password);
    if(!isPasswordValid) {
        return res.status(401).json({
            message: 'Invalid password!'
        });
    }
    const accessToken = generateToken(user);
    const decodedAccessToken: any = jwtDecode(accessToken);
    const accessTokenExpiresAt = decodedAccessToken.exp;
    const refreshToken = getRefreshToken();

    const storedRefreshToken = new Token({ refreshToken, user: user._id });
    await storedRefreshToken.save();

    res.json({
        accessToken,
        expiresAt: accessTokenExpiresAt,
        refreshToken
    });
})

app.post('/api/register', async (req: Request, res: Response) => {
  const { email, password, firstName, lastName } = req.body;

  // Password validation
  if (!passwordSchema.validate(password)) {
    return res.status(400).json({
      message: 'Password does not meet complexity requirements.'
    })
  }

  const hashedPassword = await hashPassword(password)
  const userData = {
    email: email,
    firstName: firstName,
    lastName: lastName,
    password: hashedPassword,
  }
  const existingUser = await User.findOne({ email: email }).lean()
  if(existingUser) {
    return res.status(400).json({
      message: 'Email already exists!'
    })
  }
  const user = new User(userData)
  const savedUser = await user.save()
  if(savedUser) {
    const accessToken = generateToken(savedUser);
    const decodedToken: any = jwtDecode(accessToken);
    const expiresAt = decodedToken.exp;
    const refreshToken = getRefreshToken();

    const storedRefreshToken = new Token({ refreshToken, user: savedUser._id })
    await storedRefreshToken.save()

    return res.status(200).json({
      message: 'User created successfully',
      accessToken,
      expiresAt,
      refreshToken,
    })
  }
})

app.post('/api/refreshToken', async (req: Request, res: Response) => {
  const { refreshToken } = req.body
  try {
    const tokenData = await Token.findOne({ refreshToken }).select('user')
    if(!tokenData) {
      return res.status(401).json({
        message: 'Invalid token'
      })
    }
    const existingUser = await User.findOne({_id: tokenData.user})
    if(!existingUser) {
      return res.status(401).json({
        message: 'Invalid token'
      })
    }
    const token = generateToken(existingUser)
    return res.json({accessToken: token})
  } catch (err: any) {
    return res.status(500).json({message: 'Could not refresh token'})
  }
})

const attachUser = (req: any, res: Response, next: NextFunction) => {
  const token = req.headers.authorization;
  if (!token) {
    return res
      .status(401)
      .json({ message: 'Authentication invalid' });
  }
  const decodedToken: any = jwtDecode(token.slice(7));
  if (!decodedToken) {
    return res.status(401).json({
      message: 'There was a problem authorizing the request'
    });
  } else {
    req.user = decodedToken;
    next();
  }
};

app.use(attachUser);
const requireAuth = expressjwt({
  secret: SECRET,
  audience: 'api.example.com',
  issuer: 'api.example.com',
  algorithms: ['HS256']
});

app.get('/api/test',requireAuth, async (req: Request, res: Response) => {
   const response = await axios.get('https://test.com/test', { responseType:"arraybuffer" })
   let raw = Buffer.from(response.data).toString('base64');
   res.send("data:" + response.headers["content-type"] + ";base64,"+raw);
})

async function connect() {
  const uri = process.env.MONGODB_URI as string;
  const tlsCertificateKeyFile = process.env.TLS_CERTIFICATE_KEY_FILE as string;

  mongoose.Promise = global.Promise;
  await mongoose.connect(uri, {
      sslValidate: true,
      tlsCertificateKeyFile: tlsCertificateKeyFile,
      authMechanism: 'MONGODB-X509',
      authSource: '$external'
  }).then(() => {
      console.log('Connected to MongoDB');
    })
    .catch((err: Error) => {
      console.error('Error connecting to MongoDB:', err);
    });
  
  app.listen(port);
  console.log(`Server listening on port ${port}`);
}

connect();