# Express.js + TypeScript + Prisma REST API Structure

## 📁 Struktur Folder

```
project-root/
├── src/
│   ├── controllers/
│   │   ├── auth.controller.ts
│   │   ├── user.controller.ts
│   │   └── index.ts
│   ├── middleware/
│   │   ├── auth.middleware.ts
│   │   ├── error.middleware.ts
│   │   ├── validation.middleware.ts
│   │   └── rateLimit.middleware.ts
│   ├── routes/
│   │   ├── auth.routes.ts
│   │   ├── user.routes.ts
│   │   └── index.ts
│   ├── services/
│   │   ├── auth.service.ts
│   │   ├── user.service.ts
│   │   └── email.service.ts
│   ├── utils/
│   │   ├── logger.ts
│   │   ├── response.ts
│   │   ├── jwt.ts
│   │   └── validation.ts
│   ├── types/
│   │   ├── auth.types.ts
│   │   ├── user.types.ts
│   │   └── common.types.ts
│   ├── config/
│   │   ├── database.ts
│   │   └── env.ts
│   ├── prisma/
│   │   ├── schema.prisma
│   │   └── migrations/
│   ├── tests/
│   │   ├── unit/
│   │   ├── integration/
│   │   └── setup.ts
│   └── app.ts
├── .env
├── .env.example
├── .gitignore
├── package.json
├── tsconfig.json
├── jest.config.js
├── docker-compose.yml
└── README.md
```

## 📦 Package.json

```json
{
  "name": "express-api-boilerplate",
  "version": "1.0.0",
  "description": "REST API with Express.js, TypeScript, and Prisma",
  "main": "dist/app.js",
  "scripts": {
    "dev": "tsx watch src/app.ts",
    "build": "tsc",
    "start": "node dist/app.js",
    "db:generate": "prisma generate",
    "db:push": "prisma db push",
    "db:migrate": "prisma migrate dev",
    "db:studio": "prisma studio",
    "test": "jest",
    "test:watch": "jest --watch",
    "lint": "eslint src/**/*.ts",
    "lint:fix": "eslint src/**/*.ts --fix"
  },
  "dependencies": {
    "@prisma/client": "^5.7.0",
    "express": "^4.18.2",
    "express-rate-limit": "^7.1.5",
    "helmet": "^7.1.0",
    "cors": "^2.8.5",
    "compression": "^1.7.4",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "joi": "^17.11.0",
    "winston": "^3.11.0",
    "express-async-errors": "^3.1.1",
    "nodemailer": "^6.9.7",
    "uuid": "^9.0.1"
  },
  "devDependencies": {
    "@types/express": "^4.17.21",
    "@types/node": "^20.10.4",
    "@types/bcryptjs": "^2.4.6",
    "@types/jsonwebtoken": "^9.0.5",
    "@types/cors": "^2.8.17",
    "@types/compression": "^1.7.5",
    "@types/nodemailer": "^6.4.14",
    "@types/uuid": "^9.0.7",
    "@types/jest": "^29.5.8",
    "@types/supertest": "^2.0.16",
    "typescript": "^5.3.3",
    "tsx": "^4.6.2",
    "prisma": "^5.7.0",
    "jest": "^29.7.0",
    "supertest": "^6.3.3",
    "ts-jest": "^29.1.1",
    "@typescript-eslint/eslint-plugin": "^6.13.1",
    "@typescript-eslint/parser": "^6.13.1",
    "eslint": "^8.54.0"
  }
}
```

## 🔧 Configuration Files

### tsconfig.json
```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true,
    "sourceMap": true,
    "declaration": true,
    "removeComments": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,
    "noImplicitThis": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "moduleResolution": "node",
    "baseUrl": "./",
    "paths": {
      "@/*": ["src/*"]
    }
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

### .env.example
```env
# Database
DATABASE_URL="postgresql://username:password@localhost:5432/database_name"

# JWT
JWT_SECRET="your-super-secret-jwt-key"
JWT_EXPIRES_IN="7d"

# Server
PORT=3000
NODE_ENV="development"

# Email (Optional)
SMTP_HOST="smtp.gmail.com"
SMTP_PORT=587
SMTP_USER="your-email@gmail.com"
SMTP_PASS="your-app-password"

# Redis (Optional)
REDIS_URL="redis://localhost:6379"
```

## 🗄️ Prisma Schema

### prisma/schema.prisma
```prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id        String   @id @default(cuid())
  email     String   @unique
  username  String   @unique
  password  String
  firstName String?
  lastName  String?
  avatar    String?
  role      Role     @default(USER)
  isActive  Boolean  @default(true)
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  // Relations
  posts Post[]

  @@map("users")
}

model Post {
  id        String   @id @default(cuid())
  title     String
  content   String?
  published Boolean  @default(false)
  authorId  String
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  // Relations
  author User @relation(fields: [authorId], references: [id], onDelete: Cascade)

  @@map("posts")
}

enum Role {
  USER
  ADMIN
  MODERATOR
}
```

## 🚀 Core Application Files

### src/app.ts
```typescript
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import 'express-async-errors';

import { errorHandler } from './middleware/error.middleware';
import { logger } from './utils/logger';
import routes from './routes';

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP'
});
app.use('/api/', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(compression());

// Routes
app.use('/api/v1', routes);

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Error handling
app.use(errorHandler);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});

export default app;
```

### src/config/env.ts
```typescript
import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.string().default('3000'),
  DATABASE_URL: z.string(),
  JWT_SECRET: z.string(),
  JWT_EXPIRES_IN: z.string().default('7d'),
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.string().optional(),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
});

export const env = envSchema.parse(process.env);
```

### src/utils/logger.ts
```typescript
import winston from 'winston';
import { env } from '../config/env';

const logger = winston.createLogger({
  level: env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'express-api' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

if (env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

export { logger };
```

### src/utils/response.ts
```typescript
import { Response } from 'express';

export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
  pagination?: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

export const sendResponse = <T>(
  res: Response,
  statusCode: number,
  success: boolean,
  message: string,
  data?: T,
  pagination?: ApiResponse['pagination']
): void => {
  const response: ApiResponse<T> = {
    success,
    message,
    ...(data && { data }),
    ...(pagination && { pagination })
  };

  res.status(statusCode).json(response);
};

export const sendError = (
  res: Response,
  statusCode: number,
  message: string,
  error?: string
): void => {
  const response: ApiResponse = {
    success: false,
    message,
    ...(error && { error })
  };

  res.status(statusCode).json(response);
};
```

### src/middleware/auth.middleware.ts
```typescript
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { env } from '../config/env';
import { sendError } from '../utils/response';

const prisma = new PrismaClient();

export interface AuthRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: string;
  };
}

export const authenticateToken = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      sendError(res, 401, 'Access token required');
      return;
    }

    const decoded = jwt.verify(token, env.JWT_SECRET) as any;
    
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: { id: true, email: true, role: true, isActive: true }
    });

    if (!user || !user.isActive) {
      sendError(res, 401, 'Invalid or inactive user');
      return;
    }

    req.user = user;
    next();
  } catch (error) {
    sendError(res, 403, 'Invalid token');
  }
};

export const authorizeRoles = (...roles: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      sendError(res, 401, 'Authentication required');
      return;
    }

    if (!roles.includes(req.user.role)) {
      sendError(res, 403, 'Insufficient permissions');
      return;
    }

    next();
  };
};
```

### src/middleware/validation.middleware.ts
```typescript
import { Request, Response, NextFunction } from 'express';
import Joi from 'joi';
import { sendError } from '../utils/response';

export const validate = (schema: Joi.ObjectSchema) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const { error } = schema.validate(req.body);
    
    if (error) {
      const errorMessage = error.details.map(detail => detail.message).join(', ');
      sendError(res, 400, 'Validation error', errorMessage);
      return;
    }
    
    next();
  };
};

// Validation schemas
export const authValidation = {
  register: Joi.object({
    email: Joi.string().email().required(),
    username: Joi.string().min(3).max(30).required(),
    password: Joi.string().min(6).required(),
    firstName: Joi.string().optional(),
    lastName: Joi.string().optional()
  }),

  login: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  })
};

export const userValidation = {
  update: Joi.object({
    firstName: Joi.string().optional(),
    lastName: Joi.string().optional(),
    avatar: Joi.string().uri().optional()
  })
};
```

### src/services/auth.service.ts
```typescript
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { env } from '../config/env';
import { logger } from '../utils/logger';

const prisma = new PrismaClient();

export interface RegisterData {
  email: string;
  username: string;
  password: string;
  firstName?: string;
  lastName?: string;
}

export interface LoginData {
  email: string;
  password: string;
}

export class AuthService {
  async register(data: RegisterData) {
    try {
      // Check if user already exists
      const existingUser = await prisma.user.findFirst({
        where: {
          OR: [
            { email: data.email },
            { username: data.username }
          ]
        }
      });

      if (existingUser) {
        throw new Error('User already exists');
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(data.password, 12);

      // Create user
      const user = await prisma.user.create({
        data: {
          ...data,
          password: hashedPassword
        },
        select: {
          id: true,
          email: true,
          username: true,
          firstName: true,
          lastName: true,
          role: true,
          createdAt: true
        }
      });

      // Generate token
      const token = this.generateToken(user.id);

      logger.info(`User registered: ${user.email}`);

      return { user, token };
    } catch (error) {
      logger.error('Registration error:', error);
      throw error;
    }
  }

  async login(data: LoginData) {
    try {
      // Find user
      const user = await prisma.user.findUnique({
        where: { email: data.email }
      });

      if (!user || !user.isActive) {
        throw new Error('Invalid credentials');
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(data.password, user.password);
      if (!isValidPassword) {
        throw new Error('Invalid credentials');
      }

      // Generate token
      const token = this.generateToken(user.id);

      logger.info(`User logged in: ${user.email}`);

      return {
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role
        },
        token
      };
    } catch (error) {
      logger.error('Login error:', error);
      throw error;
    }
  }

  private generateToken(userId: string): string {
    return jwt.sign(
      { userId },
      env.JWT_SECRET,
      { expiresIn: env.JWT_EXPIRES_IN }
    );
  }
}
```

### src/controllers/auth.controller.ts
```typescript
import { Request, Response } from 'express';
import { AuthService } from '../services/auth.service';
import { sendResponse, sendError } from '../utils/response';
import { logger } from '../utils/logger';

const authService = new AuthService();

export class AuthController {
  async register(req: Request, res: Response): Promise<void> {
    try {
      const result = await authService.register(req.body);
      sendResponse(res, 201, true, 'User registered successfully', result);
    } catch (error) {
      logger.error('Registration controller error:', error);
      sendError(res, 400, 'Registration failed', (error as Error).message);
    }
  }

  async login(req: Request, res: Response): Promise<void> {
    try {
      const result = await authService.login(req.body);
      sendResponse(res, 200, true, 'Login successful', result);
    } catch (error) {
      logger.error('Login controller error:', error);
      sendError(res, 401, 'Login failed', (error as Error).message);
    }
  }
}
```

### src/routes/auth.routes.ts
```typescript
import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { validate, authValidation } from '../middleware/validation.middleware';

const router = Router();
const authController = new AuthController();

router.post('/register', validate(authValidation.register), authController.register);
router.post('/login', validate(authValidation.login), authController.login);

export default router;
```

### src/routes/index.ts
```typescript
import { Router } from 'express';
import authRoutes from './auth.routes';
import userRoutes from './user.routes';

const router = Router();

router.use('/auth', authRoutes);
router.use('/users', userRoutes);

export default router;
```

## 🧪 Testing Setup

### jest.config.js
```javascript
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/tests/**',
  ],
  setupFilesAfterEnv: ['<rootDir>/src/tests/setup.ts'],
};
```

### src/tests/setup.ts
```typescript
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

beforeAll(async () => {
  // Setup test database
});

afterAll(async () => {
  await prisma.$disconnect();
});

afterEach(async () => {
  // Clean up test data
});
```

## 🐳 Docker Configuration

### docker-compose.yml
```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    depends_on:
      - postgres
    environment:
      - DATABASE_URL=postgresql://user:password@postgres:5432/mydb
      - JWT_SECRET=your-secret-key
    volumes:
      - .:/app
      - /app/node_modules

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=mydb
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

## 🚀 Getting Started

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Setup environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Setup database**
   ```bash
   npm run db:generate
   npm run db:migrate
   ```

4. **Run development server**
   ```bash
   npm run dev
   ```

5. **Run tests**
   ```bash
   npm test
   ```

## 📡 API Endpoints

### Authentication
- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Login user

### Users
- `GET /api/v1/users/profile` - Get user profile (Protected)
- `PUT /api/v1/users/profile` - Update user profile (Protected)

## 🔧 Best Practices Implemented

- **Security**: Helmet, CORS, Rate limiting, JWT authentication
- **Validation**: Joi schema validation
- **Error Handling**: Centralized error handling
- **Logging**: Winston logger with different levels
- **Database**: Prisma ORM with proper relations
- **Testing**: Jest setup with test database
- **Type Safety**: Full TypeScript implementation
- **Code Organization**: Clean architecture with separation of concerns
- **Environment**: Proper environment variable management
- **Docker**: Ready for containerization
