# Express.js Server with User Authentication

This is a back-end project which sets up an Express.js server with user authentication using JWT (JSON Web Tokens). The project includes endpoints for user registration, login and refreshing access tokens.

## Features

- Express.js server setup.
- JWT-based user authentication.
- Password validation and hashing.
- Endpoints for user login, registration, and refreshing tokens.
- Rate limiting to prevent abuse of the login and registration endpoints.

## Installation & Usage

Before you start, ensure you have Node.js and npm installed in your system.

1. **Clone the repository:**

   ```bash
   git clone https://github.com/your-username/your-repo-name.git
   cd your-repo-name
   ```

2. **Install the dependencies**:

   ```bash
   npm install
   ```

3. **Set up your environment variables:**

Create a .env file in the root of your project. Check out the .env.example file to see what variables you need to add.

4.  **Start the server**:

        ```bash
        npm start
        ```

    The server will start on the port specified in your .env file (or port 3001 as default).

**Contributing**
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

License
MIT
