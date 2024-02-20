import https from 'https';
import fs from 'fs'
import express, { Express, Request, Response, Application } from "express";
import dotenv from "dotenv";
import session from "express-session";
import memoryStore from "memorystore";
import {
  // Authentication
  generateAuthenticationOptions,
  // Registration
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { isoBase64URL, isoUint8Array } from "@simplewebauthn/server/helpers";
import type {
  GenerateAuthenticationOptionsOpts,
  GenerateRegistrationOptionsOpts,
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
  VerifyAuthenticationResponseOpts,
  VerifyRegistrationResponseOpts,
} from "@simplewebauthn/server";

import type {
  AuthenticationResponseJSON,
  AuthenticatorDevice,
  RegistrationResponseJSON,
} from "@simplewebauthn/types";
import { LoggedInUser } from "./example-server";
import { v4 as uuidv4 } from 'uuid';
import cors from "cors";
//For env File
dotenv.config();

const app: Application = express();
const MemoryStore = memoryStore(session);
const port = process.env.PORT || 8000;
const rpId = "localhost";
const expectedOrigin = "https://localhost";

app.use(express.json());
app.use(
  session({
    secret: "secret123",
    saveUninitialized: true,
    resave: false,
    cookie: {
      maxAge: 86400000,
      httpOnly: true, // Ensure to not expose session cookies to clientside scripts
    },
    store: new MemoryStore({
      checkPeriod: 86_400_000, // prune expired entries every 24h
    }),
  })
);
// const corsOpts = {
//   origin: ['http://localhost:3000', 'http://localhost:3001'],

//   methods: [
//     'GET',
//     'POST',
//   ],

//   allowedHeaders: [
//     'Content-Type',
//   ],
// };

app.use(cors());

const loggedInUserId = uuidv4();

const inMemoryUserDeviceDB: { [loggedInUserId: string]: LoggedInUser } = {
  [loggedInUserId]: {
    id: loggedInUserId,
    username: `user@${rpId}`,
    devices: [],
  },
};

app.get("/", (req: Request, res: Response) => {
  res.send("Welcome to Express & TypeScript Server");
});

app.get("/register/start", async (req: Request, res: Response) => {
  const user = inMemoryUserDeviceDB[loggedInUserId];

  const {
    /**
     * The username can be a human-readable name, email, etc... as it is intended only for display.
     */
    username,
    devices,
  } = user;
  const opts: GenerateRegistrationOptionsOpts = {
    rpName: "SimpleWebAuthn Example",
    rpID: rpId,
    userID: username,
    userName: username,
    timeout: 60000,
    attestationType: "none",
    /**
     * Passing in a user's list of already-registered authenticator IDs here prevents users from
     * registering the same device multiple times. The authenticator will simply throw an error in
     * the browser if it's asked to perform registration when one of these ID's already resides
     * on it.
     */
    authenticatorSelection: {
      residentKey: "discouraged",
      /**
       * Wondering why user verification isn't required? See here:
       *
       * https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
       */
      userVerification: "preferred",
      authenticatorAttachment: "cross-platform",
    },
    /**
     * Support the two most common algorithms: ES256, and RS256
     */
    supportedAlgorithmIDs: [-7, -257],
  };

  const options = await generateRegistrationOptions(opts);

  /**
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify an authenticator response.
   */
  req.session.currentChallenge = options.challenge;

  res.send(options);
});
app.post("/register/finish", async (req: Request, res: Response) => {
  const body: RegistrationResponseJSON = req.body;

  const user = inMemoryUserDeviceDB[loggedInUserId];

  const expectedChallenge = req.session.currentChallenge;

  let verification: VerifiedRegistrationResponse;
  try {
    const opts: VerifyRegistrationResponseOpts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpId,
      requireUserVerification: false,
    };
    verification = await verifyRegistrationResponse(opts);
  } catch (error) {
    const _error = error as Error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }

  const { verified, registrationInfo } = verification;

  if (verified && registrationInfo) {
    const { credentialPublicKey, credentialID, counter } = registrationInfo;

    const existingDevice = user.devices.find((device) =>
      isoUint8Array.areEqual(device.credentialID, credentialID)
    );

    if (!existingDevice) {
      /**
       * Add the returned device to the user's list of devices
       */
      const newDevice: AuthenticatorDevice = {
        credentialPublicKey,
        credentialID,
        counter,
        transports: body.response.transports,
      };
      user.devices.push(newDevice);
    }
  }

  req.session.currentChallenge = undefined;

  res.send({ verified });
});
app.get("/login/start", async (req: Request, res: Response) => {
  const user = inMemoryUserDeviceDB[loggedInUserId];

  const opts: GenerateAuthenticationOptionsOpts = {
    timeout: 60000,
    allowCredentials: user.devices.map((dev) => ({
      id: dev.credentialID,
      type: "public-key",
      transports: dev.transports,
    })),
    /**
     * Wondering why user verification isn't required? See here:
     *
     * https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
     */
    userVerification: "preferred",
    rpID: rpId,
  };

  const options = await generateAuthenticationOptions(opts);

  /**
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify an authenticator response.
   */
  req.session.currentChallenge = options.challenge;

  res.send(options);
});
app.post("/login/finish", async (req: Request, res: Response) => {
  const body: AuthenticationResponseJSON = req.body;

  const user = inMemoryUserDeviceDB[loggedInUserId];

  const expectedChallenge = req.session.currentChallenge;

  let dbAuthenticator;
  const bodyCredIDBuffer = isoBase64URL.toBuffer(body.rawId);
  // "Query the DB" here for an authenticator matching `credentialID`
  for (const dev of user.devices) {
    if (isoUint8Array.areEqual(dev.credentialID, bodyCredIDBuffer)) {
      dbAuthenticator = dev;
      break;
    }
  }

  if (!dbAuthenticator) {
    return res.status(400).send({
      error: "Authenticator is not registered with this site",
    });
  }

  let verification: VerifiedAuthenticationResponse;
  try {
    const opts: VerifyAuthenticationResponseOpts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpId,
      authenticator: dbAuthenticator,
      requireUserVerification: false,
    };
    verification = await verifyAuthenticationResponse(opts);
  } catch (error) {
    const _error = error as Error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    // Update the authenticator's counter in the DB to the newest count in the authentication
    dbAuthenticator.counter = authenticationInfo.newCounter;
  }

  req.session.currentChallenge = undefined;

  res.send({ verified });
});

https.createServer({
  key: fs.readFileSync('./server.key'),
  cert: fs.readFileSync('./server.crt')
},app,).listen(443,()=>{
  console.log(`🚀 Server ready at ${expectedOrigin}`);
})

// app.listen(port, () => {
//   console.log(`Server is Fire at http://localhost:${port}`);
// });
